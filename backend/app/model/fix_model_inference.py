# MODEL2_FIX_INFERENCE_ATTACK_ALL_V6_MARKER
"""
Model 2 — Fix Recommendation inference.

This module is additive only:
- It does not modify Model 1.
- It loads Model 1 embedding read-only.
- It builds semantic side features for Model 2.
- It supports old 86-dim/90-dim Model 2 weights and newer official-failure hardcase weights and calibration-v5 weights.
"""
from __future__ import annotations

import logging
import os
import re
from typing import Optional

import numpy as np

logger = logging.getLogger(__name__)

_WEIGHTS_DIR = os.path.join(os.path.dirname(__file__), "weights")
FIX_WEIGHTS_PATH = os.path.join(_WEIGHTS_DIR, "sqli_fix_model.npz")
DETECTION_WEIGHTS_PATH = os.path.join(_WEIGHTS_DIR, "sqli_model.npz")

FIX_CLASSES = {0: "A", 1: "B", 2: "C", 3: "D"}
FIX_LABELS = {
    "A": "Parameterized Query",
    "B": "Whitelist Validation",
    "C": "ORM / Query Builder Migration",
    "D": "Second-Order Mitigation",
}
LANGUAGES = ["python", "javascript", "java", "php"]
ATTACK_TYPES = ["NONE", "IN_BAND", "BLIND", "SECOND_ORDER"]

# The first 14 features preserve backward compatibility with the old 86-dim model.
# The last 4 features are semantic context features for Model 2 v2+.
EVIDENCE_FEATURES = [
    "SQL_STRING",
    "SQL_CONCAT",
    "FSTRING_SQL",
    "FSTRING_SQL_RAW",
    "UNSAFE_EXEC",
    "SAFE_EXEC",
    "WHITELIST_VAR",
    "SAFE_PLACEHOLDER_LIST",
    "SECOND_ORDER_FLOW",
    "BOOLEAN_SINK",
    "ORDER_BY_DYNAMIC",
    "TABLE_NAME_DYNAMIC",
    "RAW_VALUE_CONCAT",
    "HAS_EXECUTION_SINK",
    "VALUE_PARAMETER_CONTEXT",
    "IDENTIFIER_CONTEXT",
    "COMPLEX_BUILDER_CONTEXT",
    "STORED_SQL_CONTEXT",
    "FRAMEWORK_RAW_CONTEXT",
    "QUERY_HELPER_CONTEXT",
    "PHP_VALUE_CONTEXT",
    "TIME_BLIND_CONTEXT",
    "RAW_ALIAS_CONTEXT",
    "SECOND_ORDER_CONFIG_ORDER_CONTEXT",
    # Attack-all calibration v6 features: help Model 2 learn A-vs-C and D-vs-A without rule overrides.
    "SIMPLE_VALUE_QUERY_CONTEXT",
    "PHP_SCALAR_CONCAT_CONTEXT",
    "VALUE_LIST_CONTEXT",
    "LIMIT_OFFSET_CONTEXT",
    "SIMPLE_FRAMEWORK_VALUE_CONTEXT",
    "COMPLEX_LOOP_BUILDER_CONTEXT",
    "SQL_FRAGMENT_COMPOSER_CONTEXT",
    "DIRECT_STORED_EXEC_CONTEXT",
    # Attack-all v6 features for the remaining full-pipeline failure families.
    "PYTHON_SIMPLE_VALUE_CONCAT_CONTEXT",
    "PYTHON_SANITIZED_LIKE_CONTEXT",
    "PYTHON_EXEC_ALIAS_CONTEXT",
    "JS_DIRECT_TEMPLATE_VALUE_CONTEXT",
    "JS_REQUEST_SEGMENT_VALUE_CONTEXT",
    "SEQUELIZE_RAW_TEMPLATE_CONTEXT",
    "JPA_NATIVE_RAW_CONTEXT",
    "DB_ROW_STORED_SQL_EXEC_CONTEXT",
]

_fix_weights: Optional[dict] = None
_fix_load_attempted = False
_emb_W_cache: Optional[np.ndarray] = None


def load_shared_embedding() -> Optional[np.ndarray]:
    global _emb_W_cache
    if _emb_W_cache is not None:
        return _emb_W_cache
    if not os.path.isfile(DETECTION_WEIGHTS_PATH):
        return None
    try:
        _emb_W_cache = np.load(DETECTION_WEIGHTS_PATH, allow_pickle=False)["emb_W"].astype(np.float32)
        return _emb_W_cache
    except Exception as exc:
        logger.error("Failed loading Model 1 embedding for Model 2: %s", exc)
        return None


def _load_fix_model() -> Optional[dict]:
    global _fix_weights, _fix_load_attempted
    if _fix_load_attempted:
        return _fix_weights
    _fix_load_attempted = True
    if not os.path.isfile(FIX_WEIGHTS_PATH):
        logger.warning("Model 2 weights not found at %s", FIX_WEIGHTS_PATH)
        return None
    try:
        w = dict(np.load(FIX_WEIGHTS_PATH, allow_pickle=False))
        required = {"m2_dense1_W", "m2_dense1_b", "m2_dense2_W", "m2_dense2_b"}
        missing = required - set(w)
        if missing:
            logger.error("Model 2 weights missing keys: %s", sorted(missing))
            return None
        _fix_weights = w
        return w
    except Exception as exc:
        logger.error("Failed loading Model 2 weights: %s", exc)
        return None


def _softmax(x: np.ndarray) -> np.ndarray:
    e = np.exp(x - np.max(x))
    return e / e.sum()


def _relu(x: np.ndarray) -> np.ndarray:
    return np.maximum(0.0, x)


def _one_hot(value: str | None, choices: list[str]) -> np.ndarray:
    out = np.zeros(len(choices), dtype=np.float32)
    if value:
        vals = [c.lower() for c in choices]
        v = value.lower()
        if v in vals:
            out[vals.index(v)] = 1.0
    return out


def _strip_comments(code: str, language: str | None) -> str:
    if (language or "").lower() == "python":
        return re.sub(r"#.*", "", code)
    code = re.sub(r"/\*.*?\*/", "", code, flags=re.S)
    return re.sub(r"//[^\n\r]*", "", code)


def _rx(pattern: str, text: str, flags: int = re.I | re.S) -> bool:
    return re.search(pattern, text, flags) is not None


def _detect_order_by_dynamic(c: str) -> bool:
    return _rx(
        r"\bORDER\s+BY\s*(?:"
        r"[\"'`]\s*(?:\+|\.)\s*\$?[A-Za-z_$]\w*"
        r"|(?:\+|\.)\s*\$?[A-Za-z_$]\w*"
        r"|\{\s*[A-Za-z_$]\w*\s*\}"
        r"|\$\{\s*[A-Za-z_$]\w*\s*\}"
        r")",
        c,
    )


def _detect_table_name_dynamic(c: str) -> bool:
    return _rx(
        r"\b(?:FROM|JOIN|UPDATE|INTO)\s*(?:"
        r"[\"'`]\s*(?:\+|\.)\s*\$?[A-Za-z_$]\w*"
        r"|(?:\+|\.)\s*\$?[A-Za-z_$]\w*"
        r"|\{\s*[A-Za-z_$]\w*\s*\}"
        r"|\$\{\s*[A-Za-z_$]\w*\s*\}"
        r")",
        c,
    )


def _detect_value_parameter_context(c: str) -> bool:
    # User-controlled value appears in value position: WHERE/VALUES/SET comparison or assignment.
    return (
        _rx(r"\bWHERE\b[\s\S]{0,220}(?:=|LIKE|>|<|>=|<=)\s*(?:[\"']\s*)?(?:\+|\.)\s*\$?[A-Za-z_$]\w*", c)
        or _rx(r"\bWHERE\b[\s\S]{0,220}(?:=|LIKE|>|<|>=|<=)[\s\S]{0,80}(?:\{\s*[A-Za-z_$]\w*\s*\}|\$\{\s*[A-Za-z_$]\w*\s*\})", c)
        or _rx(r"\bVALUES\s*\([\s\S]{0,180}(?:\+|\.)\s*\$?[A-Za-z_$]\w*", c)
        or _rx(r"\bSET\b[\s\S]{0,180}=\s*(?:[\"']\s*)?(?:\+|\.)\s*\$?[A-Za-z_$]\w*", c)
        or _rx(r"\bCOUNT\s*\([\s\S]{0,120}\bWHERE\b[\s\S]{0,180}(?:\+|\.|\$\{|\{)", c)
    )


def _detect_framework_raw_context(c: str) -> bool:
    return _rx(
        r"(?:sqlalchemy\.text|\btext\s*\(|sequelize\.query|knex\.raw|DB::raw|createNativeQuery|nativeQuery|"
        r"entityManager\.createNativeQuery|createQuery\s*\(|jdbc\.query|queryForList|\$wpdb->query|mysqli_query)",
        c,
    )


def _detect_query_helper_context(c: str) -> bool:
    return _rx(
        r"\b(?:build|make|compose|create|assemble|render|prepare)[A-Za-z0-9_]*(?:sql|query|where|filter|search|report)[A-Za-z0-9_]*\s*\(",
        c,
    )


def _detect_php_value_context(c: str) -> bool:
    return _rx(r"\$\w+\s*=\s*[\"'][^\n;]*(?:SELECT|INSERT|UPDATE|DELETE)[^\n;]*[\"'][\s\S]{0,160}\.\s*\$\w+", c) and _rx(r"->\s*(?:query|exec)\s*\(\s*\$\w+", c)


def _detect_time_blind_context(c: str) -> bool:
    return _rx(r"\b(?:SLEEP|pg_sleep|WAITFOR\s+DELAY|BENCHMARK)\s*\(", c)


def _detect_raw_alias_context(c: str) -> bool:
    return _rx(r"\b(?:raw|unsafe|alias|sqlText|queryText|statement)\b[\s\S]{0,220}(?:execute|query|all|get|run|exec)", c)


def _detect_value_list_context(c: str) -> bool:
    return _rx(
        r"(?:\bIN\s*\(|implode\s*\(|join\s*\(|array_map\s*\(|map\s*\(|ids\.join|String\.join)",
        c,
    ) and _rx(r"(?:WHERE|SELECT|UPDATE|DELETE|INSERT)[\s\S]{0,260}(?:\+|\.|\$\{|\{)", c)


def _detect_limit_offset_context(c: str) -> bool:
    return _rx(r"\b(?:LIMIT|OFFSET)\b[\s\S]{0,120}(?:\+|\.|\$\{|\{|\$[A-Za-z_]\w*)", c)


def _detect_simple_framework_value_context(c: str) -> bool:
    # Framework/native APIs can still be repaired with parameters when the raw SQL
    # contains one scalar value interpolation rather than a dynamic field/table builder.
    framework_call = _detect_framework_raw_context(c)
    simple_value = _detect_value_parameter_context(c) or _detect_php_value_context(c) or _detect_time_blind_context(c)
    return bool(framework_call and simple_value and not (_detect_order_by_dynamic(c) or _detect_table_name_dynamic(c)))


def _detect_complex_loop_builder_context(c: str) -> bool:
    loop_or_collection = _rx(
        r"\b(?:for|foreach)\b[\s\S]{0,260}(?:filters|criteria|whereMap|searchFields|params|Object\.keys|keySet|items\s*\(|implode|join|parts|clauses|conditions)",
        c,
    )
    incremental_sql = _rx(
        r"(?:sql|query|where|parts|where_parts|clauses|conditions)[\s\S]{0,280}(?:\+=|\.append\s*\(|\.push\s*\(|\.add\s*\(|\.\=|join\s*\(|implode\s*\()",
        c,
    )
    dynamic_field = _rx(r"(?:field|key|k)\s*(?:\+|\.|\})", c) or _rx(r"(?:filters|criteria|whereMap|params)\s*\[", c)
    return bool(loop_or_collection and (incremental_sql or dynamic_field))


def _detect_sql_fragment_composer_context(c: str) -> bool:
    return _rx(
        r"\b(?:build|make|compose|create|assemble|render)[A-Za-z0-9_]*(?:sql|query|where|filter|search|report)[A-Za-z0-9_]*\s*\(\s*(?:filters|criteria|whereMap|params|conditions|searchFields)",
        c,
    )


def _detect_direct_stored_exec_context(c: str) -> bool:
    return _rx(
        r"(?:fetchColumn|getString|row\s*\[|cache\.get|config\.get|loadSaved|load_saved|saved|stored|cached|sql_text|saved_filter|where_clause|order_clause)"
        r"[\s\S]{0,320}(?:execute|executeQuery|query|all|get|run|exec|cursor\.execute|->query)",
        c,
    )


def _detect_second_order_config_order_context(c: str) -> bool:
    return _rx(
        r"(?:saved|stored|cached|cache|config|db|database|row|record)[A-Za-z0-9_]*(?:sql|query|filter|where|order|fragment|clause|text)|"
        r"(?:sql_text|saved_filter|savedFilter|cached_fragment|cachedWhere|cached_where|where_clause|order_clause|stored_filter|report_sql)",
        c,
    ) and _rx(r"(?:execute|executeQuery|query|all|get|run|exec|cursor\.execute|->query)", c)


def _detect_complex_builder_context(c: str) -> bool:
    # C is reserved for complex builders: map/list driven clauses, dynamic fields,
    # or helpers that compose SQL fragments from filter/criteria objects. Simple
    # framework raw SQL with one scalar value remains an A-style repair.
    return bool(_detect_complex_loop_builder_context(c) or _detect_sql_fragment_composer_context(c))


def _detect_stored_sql_context(c: str) -> bool:
    return _rx(
        r"(?:sql_text|saved_filter|savedFilter|where_clause|cached_where|stored_filter|report_sql|cache\.get|config\.get|fetchColumn|getString)"
        r"[\s\S]{0,260}(?:execute|executeQuery|query|all|get|run|exec)",
        c,
    )



def _detect_python_simple_value_concat_context(c: str, language: str | None) -> bool:
    if (language or "").lower() != "python":
        return False
    return (
        _rx(r"\b(?:sql|query|statement|q)\s*=\s*(?:f)?[\"'][\s\S]{0,240}\b(?:WHERE|LIKE|DELETE\s+FROM|COUNT\s*\()[\s\S]{0,180}(?:\+|\{[A-Za-z_]\w*\})", c)
        or _rx(r"\b(?:conn|cursor|cur|self\.conn|session)\s*\.\s*execute(?:script)?\s*\([^)]*(?:sql|query|statement|q)", c)
    ) and not _rx(r"\bORDER\s+BY\b[\s\S]{0,120}(?:\+|\{|\$\{)", c)


def _detect_python_sanitized_like_context(c: str, language: str | None) -> bool:
    if (language or "").lower() != "python":
        return False
    return _rx(r"\.replace\s*\(\s*[\"']'[\s\S]{0,180}\bLIKE\b[\s\S]{0,220}\+", c)


def _detect_python_exec_alias_context(c: str, language: str | None) -> bool:
    if (language or "").lower() != "python":
        return False
    return (
        _rx(r"\b(?:runner|execute_fn|exec_fn)\s*=\s*\w+\.execute\b[\s\S]{0,240}\b(?:runner|execute_fn|exec_fn)\s*\(", c)
        or _rx(r"\bdef\s+run_query\s*\([\s\S]{0,260}\.execute\s*\(\s*statement\s*\)[\s\S]{0,260}\bbuild_query\s*\(", c)
    )


def _detect_js_direct_template_value_context(c: str, language: str | None) -> bool:
    if (language or "").lower() != "javascript":
        return False
    return _rx(r"`[\s\S]{0,240}\bWHERE\b[\s\S]{0,120}\$\{[A-Za-z_$]\w*\}[\s\S]{0,160}`[\s\S]{0,120}\.(?:all|get|query|execute)\s*\(", c)


def _detect_js_request_segment_value_context(c: str, language: str | None) -> bool:
    if (language or "").lower() != "javascript":
        return False
    return _rx(r"\b(?:storedSegment|configWhereClause|savedSegment)\b[\s\S]{0,120}req\.query", c) and _rx(
        r"\b(?:sql|query)\s*=[\s\S]{0,180}(?:\+|\$\{)\s*(?:storedSegment|configWhereClause|savedSegment)", c
    )


def _detect_sequelize_raw_template_context(c: str, language: str | None) -> bool:
    if (language or "").lower() != "javascript":
        return False
    return _rx(r"\bsequelize\.query\s*\(", c) and _rx(r"`[\s\S]{0,260}\$\{[A-Za-z_$]\w*\}", c)


def _detect_jpa_native_raw_context(c: str, language: str | None) -> bool:
    if (language or "").lower() != "java":
        return False
    return _rx(r"\bcreateNativeQuery\s*\(", c) and _rx(r"\bString\s+sql\s*=[\s\S]{0,260}\+", c)


def _detect_db_row_stored_sql_exec_context(c: str, language: str | None) -> bool:
    return (
        _rx(r"\bSELECT\b[\s\S]{0,180}(?:sql_text|saved_filter|where_clause|widget_filter|query_text|stored_query)", c)
        and _rx(r"\b(?:row|rs|record|result)[\s\S]{0,280}(?:sql_text|saved_filter|where_clause|filter|query)", c)
        and _rx(r"\.(?:execute|executeQuery|query|all|get|run)\s*\([^)]*(?:saved|stored|filter|sql|query|where)", c)
    )


def _raw_features(raw_code: str | None, language: str | None) -> dict[str, float]:
    if not raw_code:
        return {}
    c = _strip_comments(raw_code, language)
    order_dynamic = _detect_order_by_dynamic(c)
    table_dynamic = _detect_table_name_dynamic(c)
    value_context = _detect_value_parameter_context(c)
    complex_loop_context = _detect_complex_loop_builder_context(c)
    sql_fragment_composer = _detect_sql_fragment_composer_context(c)
    complex_context = _detect_complex_builder_context(c)
    stored_context = _detect_stored_sql_context(c) or _detect_second_order_config_order_context(c) or _detect_direct_stored_exec_context(c)
    framework_context = _detect_framework_raw_context(c)
    helper_context = _detect_query_helper_context(c)
    php_value_context = _detect_php_value_context(c)
    time_blind_context = _detect_time_blind_context(c)
    raw_alias_context = _detect_raw_alias_context(c)
    second_order_config_order = _detect_second_order_config_order_context(c)
    value_list_context = _detect_value_list_context(c)
    limit_offset_context = _detect_limit_offset_context(c)
    simple_framework_value = _detect_simple_framework_value_context(c)
    direct_stored_exec = _detect_direct_stored_exec_context(c)
    python_simple_value = _detect_python_simple_value_concat_context(c, language)
    python_sanitized_like = _detect_python_sanitized_like_context(c, language)
    python_exec_alias = _detect_python_exec_alias_context(c, language)
    js_direct_template_value = _detect_js_direct_template_value_context(c, language)
    js_request_segment_value = _detect_js_request_segment_value_context(c, language)
    sequelize_raw_template = _detect_sequelize_raw_template_context(c, language)
    jpa_native_raw = _detect_jpa_native_raw_context(c, language)
    db_row_stored_exec = _detect_db_row_stored_sql_exec_context(c, language)
    complex_context = complex_context or sequelize_raw_template or jpa_native_raw
    stored_context = stored_context or db_row_stored_exec
    simple_value_context = (
        value_context or php_value_context or time_blind_context or raw_alias_context
        or value_list_context or limit_offset_context or simple_framework_value
        or python_simple_value or python_sanitized_like or python_exec_alias
        or js_direct_template_value or js_request_segment_value
    ) and not (order_dynamic or table_dynamic or complex_context or stored_context)
    has_sink = _rx(
        r"\.\s*(?:execute|executeQuery|executeUpdate|query|all|get|run|each|exec|raw)\s*\(|"
        r"->\s*(?:query|exec|execute|prepare)\s*\(|mysqli_query\s*\(",
        c,
    )
    return {
        "ORDER_BY_DYNAMIC": float(order_dynamic),
        "TABLE_NAME_DYNAMIC": float(table_dynamic),
        "RAW_VALUE_CONCAT": float(simple_value_context),
        "HAS_EXECUTION_SINK": float(has_sink),
        "VALUE_PARAMETER_CONTEXT": float(simple_value_context),
        "IDENTIFIER_CONTEXT": float(order_dynamic or table_dynamic),
        "COMPLEX_BUILDER_CONTEXT": float(complex_context),
        "STORED_SQL_CONTEXT": float(stored_context),
        "FRAMEWORK_RAW_CONTEXT": float(framework_context),
        "QUERY_HELPER_CONTEXT": float(helper_context),
        "PHP_VALUE_CONTEXT": float(php_value_context),
        "TIME_BLIND_CONTEXT": float(time_blind_context),
        "RAW_ALIAS_CONTEXT": float(raw_alias_context and not stored_context and not complex_context),
        "SECOND_ORDER_CONFIG_ORDER_CONTEXT": float(second_order_config_order),
        "SIMPLE_VALUE_QUERY_CONTEXT": float(simple_value_context),
        "PHP_SCALAR_CONCAT_CONTEXT": float(php_value_context and not complex_context and not stored_context),
        "VALUE_LIST_CONTEXT": float(value_list_context and not stored_context),
        "LIMIT_OFFSET_CONTEXT": float(limit_offset_context and not stored_context),
        "SIMPLE_FRAMEWORK_VALUE_CONTEXT": float(simple_framework_value and not stored_context),
        "COMPLEX_LOOP_BUILDER_CONTEXT": float(complex_loop_context),
        "SQL_FRAGMENT_COMPOSER_CONTEXT": float(sql_fragment_composer),
        "DIRECT_STORED_EXEC_CONTEXT": float(direct_stored_exec),
        "PYTHON_SIMPLE_VALUE_CONCAT_CONTEXT": float(python_simple_value and not stored_context and not complex_context),
        "PYTHON_SANITIZED_LIKE_CONTEXT": float(python_sanitized_like and not stored_context),
        "PYTHON_EXEC_ALIAS_CONTEXT": float(python_exec_alias and not stored_context),
        "JS_DIRECT_TEMPLATE_VALUE_CONTEXT": float(js_direct_template_value and not stored_context and not complex_context),
        "JS_REQUEST_SEGMENT_VALUE_CONTEXT": float(js_request_segment_value and not stored_context),
        "SEQUELIZE_RAW_TEMPLATE_CONTEXT": float(sequelize_raw_template),
        "JPA_NATIVE_RAW_CONTEXT": float(jpa_native_raw),
        "DB_ROW_STORED_SQL_EXEC_CONTEXT": float(db_row_stored_exec),
    }


def build_evidence_vector(
    normalized_tokens: list[str] | None = None,
    raw_code: str | None = None,
    language: str | None = None,
) -> np.ndarray:
    token_set = set(normalized_tokens or [])
    raw = _raw_features(raw_code, language)
    return np.array(
        [1.0 if name in token_set else float(raw.get(name, 0.0)) for name in EVIDENCE_FEATURES],
        dtype=np.float32,
    )


def _pooled_embedding(ids: np.ndarray, emb_W: np.ndarray) -> np.ndarray:
    ids = np.clip(ids.astype(np.int32), 0, emb_W.shape[0] - 1)
    mask = ids != 0
    if np.any(mask):
        return emb_W[ids[mask]].mean(axis=0).astype(np.float32)
    return np.zeros(emb_W.shape[1], dtype=np.float32)


def _model_input(
    token_ids: list[int],
    emb_W: np.ndarray,
    input_dim: int,
    language=None,
    attack_type=None,
    normalized_tokens=None,
    raw_code=None,
) -> np.ndarray:
    pooled = _pooled_embedding(np.array(token_ids, dtype=np.int32), emb_W)
    if input_dim <= pooled.shape[0]:
        return pooled[:input_dim]
    side = np.concatenate(
        [
            _one_hot(language, LANGUAGES),
            _one_hot(attack_type, ATTACK_TYPES),
            build_evidence_vector(normalized_tokens, raw_code, language),
        ]
    ).astype(np.float32)
    x = np.concatenate([pooled, side]).astype(np.float32)
    return np.pad(x, (0, max(0, input_dim - len(x))))[:input_dim]


def _model_version_from_weights(w: dict) -> str:
    try:
        if "model2_version" in w:
            return str(w["model2_version"].tolist())
    except Exception:
        pass
    return "model2_fix_rewrite_v1"


def run_fix_inference(
    token_ids: list[int],
    emb_W: Optional[np.ndarray] = None,
    *,
    language: str | None = None,
    attack_type: str | None = None,
    normalized_tokens: list[str] | None = None,
    raw_code: str | None = None,
) -> Optional[dict]:
    w = _load_fix_model()
    emb_W = emb_W if emb_W is not None else load_shared_embedding()
    if w is None or emb_W is None:
        return None
    W1 = w["m2_dense1_W"].astype(np.float32)
    b1 = w["m2_dense1_b"].astype(np.float32)
    W2 = w["m2_dense2_W"].astype(np.float32)
    b2 = w["m2_dense2_b"].astype(np.float32)
    x = _model_input(token_ids, emb_W, W1.shape[1], language, attack_type, normalized_tokens, raw_code)
    probs = _softmax(W2 @ _relu(W1 @ x + b1) + b2)
    idx = int(np.argmax(probs))
    ft = FIX_CLASSES[idx]
    return {
        "fixType": ft,
        "fixStrategy": FIX_LABELS[ft],
        "confidence": round(float(probs[idx]), 4),
        "allProbabilities": {FIX_CLASSES[i]: round(float(p), 4) for i, p in enumerate(probs)},
        "modelVersion": _model_version_from_weights(w),
    }


def fix_model_is_loaded() -> bool:
    return _load_fix_model() is not None and load_shared_embedding() is not None
