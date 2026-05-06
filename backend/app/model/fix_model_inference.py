"""
Model 2 — Fix Recommendation inference.
Additive only: does not affect Model 1 detection. Reuses Model 1 embedding read-only.
Supports legacy pooled-only weights and new pooled+language+attack+evidence weights.
"""
from __future__ import annotations
import logging, os, re
from typing import Optional
import numpy as np
logger = logging.getLogger(__name__)
_WEIGHTS_DIR = os.path.join(os.path.dirname(__file__), "weights")
FIX_WEIGHTS_PATH = os.path.join(_WEIGHTS_DIR, "sqli_fix_model.npz")
DETECTION_WEIGHTS_PATH = os.path.join(_WEIGHTS_DIR, "sqli_model.npz")
FIX_CLASSES = {0: "A", 1: "B", 2: "C", 3: "D"}
FIX_LABELS = {"A": "Parameterized Query", "B": "Whitelist Validation", "C": "ORM / Query Builder Migration", "D": "Second-Order Mitigation"}
LANGUAGES = ["python", "javascript", "java", "php"]
ATTACK_TYPES = ["NONE", "IN_BAND", "BLIND", "SECOND_ORDER"]
EVIDENCE_FEATURES = ["SQL_STRING","SQL_CONCAT","FSTRING_SQL","FSTRING_SQL_RAW","UNSAFE_EXEC","SAFE_EXEC","WHITELIST_VAR","SAFE_PLACEHOLDER_LIST","SECOND_ORDER_FLOW","BOOLEAN_SINK","ORDER_BY_DYNAMIC","TABLE_NAME_DYNAMIC","RAW_VALUE_CONCAT","HAS_EXECUTION_SINK"]
_fix_weights: Optional[dict] = None
_fix_load_attempted = False
_emb_W_cache: Optional[np.ndarray] = None

def load_shared_embedding() -> Optional[np.ndarray]:
    global _emb_W_cache
    if _emb_W_cache is not None: return _emb_W_cache
    if not os.path.isfile(DETECTION_WEIGHTS_PATH): return None
    try:
        _emb_W_cache = np.load(DETECTION_WEIGHTS_PATH, allow_pickle=False)["emb_W"].astype(np.float32)
        return _emb_W_cache
    except Exception as exc:
        logger.error("Failed loading Model 1 embedding for Model 2: %s", exc); return None

def _load_fix_model() -> Optional[dict]:
    global _fix_weights, _fix_load_attempted
    if _fix_load_attempted: return _fix_weights
    _fix_load_attempted = True
    if not os.path.isfile(FIX_WEIGHTS_PATH):
        logger.warning("Model 2 weights not found at %s", FIX_WEIGHTS_PATH); return None
    try:
        w = dict(np.load(FIX_WEIGHTS_PATH, allow_pickle=False))
        required = {"m2_dense1_W","m2_dense1_b","m2_dense2_W","m2_dense2_b"}
        if required - set(w):
            logger.error("Model 2 weights missing keys: %s", sorted(required - set(w))); return None
        _fix_weights = w; return w
    except Exception as exc:
        logger.error("Failed loading Model 2 weights: %s", exc); return None

def _softmax(x: np.ndarray) -> np.ndarray:
    e = np.exp(x - np.max(x)); return e / e.sum()
def _relu(x: np.ndarray) -> np.ndarray: return np.maximum(0.0, x)
def _one_hot(value: str | None, choices: list[str]) -> np.ndarray:
    out = np.zeros(len(choices), dtype=np.float32)
    if value:
        vals = [c.lower() for c in choices]; v = value.lower()
        if v in vals: out[vals.index(v)] = 1.0
    return out

def _strip_comments(code: str, language: str | None) -> str:
    if (language or "").lower() == "python": return re.sub(r"#.*", "", code)
    code = re.sub(r"/\*.*?\*/", "", code, flags=re.S)
    return re.sub(r"//[^\n\r]*", "", code)
def _rx(p: str, t: str, flags: int = re.I | re.S) -> bool: return re.search(p, t, flags) is not None

def _raw_features(raw_code: str | None, language: str | None) -> dict[str, float]:
    if not raw_code: return {}
    c = _strip_comments(raw_code, language)
    return {
        "ORDER_BY_DYNAMIC": float(_rx(r"ORDER\s+BY[\s\S]{0,140}(?:\+\s*\w+|\$\{|\.\s*\$\w+)", c)),
        "TABLE_NAME_DYNAMIC": float(_rx(r"FROM[\s\S]{0,100}(?:\+\s*\w+|\$\{|\.\s*\$\w+)", c)),
        "RAW_VALUE_CONCAT": float(_rx(r"WHERE[\s\S]{0,180}(?:\+\s*\w+|\$\{|\.\s*\$\w+)", c) or _rx(r"(?:SELECT|UPDATE|DELETE|INSERT)[\s\S]{0,240}\+\s*\w+", c)),
        "HAS_EXECUTION_SINK": float(_rx(r"\.\s*(?:execute|executeQuery|executeUpdate|query|all|get|run|each|exec)\s*\(|->\s*(?:query|exec|execute|prepare)\s*\(|mysqli_query\s*\(", c)),
    }

def build_evidence_vector(normalized_tokens: list[str] | None = None, raw_code: str | None = None, language: str | None = None) -> np.ndarray:
    s = set(normalized_tokens or []); raw = _raw_features(raw_code, language)
    return np.array([1.0 if name in s else float(raw.get(name, 0.0)) for name in EVIDENCE_FEATURES], dtype=np.float32)

def _pooled_embedding(ids: np.ndarray, emb_W: np.ndarray) -> np.ndarray:
    ids = np.clip(ids.astype(np.int32), 0, emb_W.shape[0]-1); mask = ids != 0
    return emb_W[ids[mask]].mean(axis=0).astype(np.float32) if np.any(mask) else np.zeros(emb_W.shape[1], dtype=np.float32)

def _model_input(token_ids: list[int], emb_W: np.ndarray, input_dim: int, language=None, attack_type=None, normalized_tokens=None, raw_code=None) -> np.ndarray:
    pooled = _pooled_embedding(np.array(token_ids, dtype=np.int32), emb_W)
    if input_dim <= pooled.shape[0]: return pooled[:input_dim]
    side = np.concatenate([_one_hot(language, LANGUAGES), _one_hot(attack_type, ATTACK_TYPES), build_evidence_vector(normalized_tokens, raw_code, language)]).astype(np.float32)
    x = np.concatenate([pooled, side]).astype(np.float32)
    return np.pad(x, (0, max(0, input_dim-len(x))))[:input_dim]

def run_fix_inference(token_ids: list[int], emb_W: Optional[np.ndarray] = None, *, language: str | None = None, attack_type: str | None = None, normalized_tokens: list[str] | None = None, raw_code: str | None = None) -> Optional[dict]:
    w = _load_fix_model(); emb_W = emb_W if emb_W is not None else load_shared_embedding()
    if w is None or emb_W is None: return None
    W1=w["m2_dense1_W"].astype(np.float32); b1=w["m2_dense1_b"].astype(np.float32); W2=w["m2_dense2_W"].astype(np.float32); b2=w["m2_dense2_b"].astype(np.float32)
    x = _model_input(token_ids, emb_W, W1.shape[1], language, attack_type, normalized_tokens, raw_code)
    probs = _softmax(W2 @ _relu(W1 @ x + b1) + b2)
    idx = int(np.argmax(probs)); ft = FIX_CLASSES[idx]
    return {"fixType": ft, "fixStrategy": FIX_LABELS[ft], "confidence": round(float(probs[idx]),4), "allProbabilities": {FIX_CLASSES[i]: round(float(p),4) for i,p in enumerate(probs)}, "modelVersion": "model2_fix_rewrite_v1"}

def fix_model_is_loaded() -> bool: return _load_fix_model() is not None and load_shared_embedding() is not None
