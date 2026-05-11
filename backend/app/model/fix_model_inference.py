# MODEL2_FIX_INFERENCE_CONTEXT_FEATURES_MARKER
"""
Model 2 — Fix Recommendation inference.

This module is additive only:
- It does not modify Model 1.
- It loads Model 1 embedding read-only.
- It builds semantic side features for Model 2.
- It supports old 86-dim Model 2 weights and newer context-feature weights.
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


def _detect_complex_builder_context(c: str) -> bool:
    # Complex dynamic query builders build clauses from maps/lists/loops, not a single value parameter.
    loop_or_collection = _rx(
        r"\b(?:for|foreach)\b[\s\S]{0,180}(?:filters|criteria|whereMap|searchFields|params|Object\.keys|keySet|items\s*\(|implode|join)",
        c,
    )
    incremental_sql = _rx(
        r"(?:sql|query|where|parts|where_parts)[\s\S]{0,220}(?:\+=|\.append\s*\(|\.push\s*\(|\.add\s*\(|\.\=|join\s*\(|implode\s*\()",
        c,
    )
    dynamic_field = _rx(r"(?:field|key|k)\s*(?:\+|\.|\})", c) or _rx(r"(?:filters|criteria|whereMap|params)\s*\[", c)
    return bool((loop_or_collection and incremental_sql) or (incremental_sql and dynamic_field))


def _detect_stored_sql_context(c: str) -> bool:
    return _rx(
        r"(?:sql_text|saved_filter|savedFilter|where_clause|cached_where|stored_filter|report_sql|cache\.get|config\.get|fetchColumn|getString)"
        r"[\s\S]{0,260}(?:execute|executeQuery|query|all|get|run|exec)",
        c,
    )


def _raw_features(raw_code: str | None, language: str | None) -> dict[str, float]:
    if not raw_code:
        return {}
    c = _strip_comments(raw_code, language)
    order_dynamic = _detect_order_by_dynamic(c)
    table_dynamic = _detect_table_name_dynamic(c)
    value_context = _detect_value_parameter_context(c)
    complex_context = _detect_complex_builder_context(c)
    stored_context = _detect_stored_sql_context(c)
    has_sink = _rx(
        r"\.\s*(?:execute|executeQuery|executeUpdate|query|all|get|run|each|exec|raw)\s*\(|"
        r"->\s*(?:query|exec|execute|prepare)\s*\(|mysqli_query\s*\(",
        c,
    )
    return {
        "ORDER_BY_DYNAMIC": float(order_dynamic),
        "TABLE_NAME_DYNAMIC": float(table_dynamic),
        "RAW_VALUE_CONCAT": float(value_context and not (order_dynamic or table_dynamic)),
        "HAS_EXECUTION_SINK": float(has_sink),
        "VALUE_PARAMETER_CONTEXT": float(value_context and not (order_dynamic or table_dynamic or complex_context or stored_context)),
        "IDENTIFIER_CONTEXT": float(order_dynamic or table_dynamic),
        "COMPLEX_BUILDER_CONTEXT": float(complex_context),
        "STORED_SQL_CONTEXT": float(stored_context),
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
