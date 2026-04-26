"""
Scan service — two-model pipeline.

Model 1 (Detection): runs on every upload, uses chunk-level max-pooling.
Model 2 (Fix):       runs only when user clicks "Generate Fix".
"""
from pathlib import Path

from bson import ObjectId
from fastapi import HTTPException, UploadFile

from app.core.constants import ALLOWED_EXTENSIONS
from app.db.database import get_audit_logs_collection
from app.preprocessing.code_cleaner import clean_code
from app.preprocessing.tokenizer import tokenize_code
from app.preprocessing.normalizer import normalize_tokens
from app.preprocessing.chunker import split_into_chunks
from app.schemas.scan import (
    CleanCodePayload,
    GenerateFixResponse,
    NormalizedCodePayload,
    RawCodePayload,
    ScanDetectionInfo,
    ScanFileInfo,
    ScanHistoryItemResponse,
    ScanHistoryListResponse,
    ScanPreprocessingInfo,
    ScanResponse,
    ScanVectorizationInfo,
    SuspiciousPattern,
    TokenizedCodePayload,
)
from app.services.audit_log_service import log_audit_event
from app.vectorization.vocabulary import build_fixed_vocabulary
from app.vectorization.vectorizer import vectorize_tokens
from app.model.inference import run_inference
from app.fix_engine.fix_generator import generate_fix

VOCABULARY = build_fixed_vocabulary()

# ── Signal severity weights ───────────────────────────────────────────────────

# HIGH signals that alone (or in combination) prove a vulnerability
HIGH_SIGNALS = {"FSTRING_SQL", "SQL_CONCAT"}

# Signals that are dangerous when combined with a SQL context
MEDIUM_SIGNALS = {"UNSAFE_EXEC"}

# Signals that indicate parameterized / safe usage
SAFE_SIGNALS = {"SAFE_EXEC"}

# These combos are ALWAYS vulnerable — hard override ignores the ML score
ALWAYS_VULNERABLE_COMBOS = [
    {"SQL_CONCAT", "UNSAFE_EXEC"},   # concat + unsafe exec
    {"FSTRING_SQL", "UNSAFE_EXEC"},  # f-string injection + unsafe exec
    {"FSTRING_SQL"},                 # f-string SQL alone is enough
    {"SQL_CONCAT"},                  # concat alone is enough
]


# ── Language detection ────────────────────────────────────────────────────────

def detect_language(filename: str) -> str:
    suffix = Path(filename).suffix.lower()
    if suffix not in ALLOWED_EXTENSIONS:
        raise HTTPException(
            status_code=400,
            detail=f"Unsupported file type '{suffix}'. Allowed: .py, .js, .php, .java",
        )
    return ALLOWED_EXTENSIONS[suffix]


# ── File reading ──────────────────────────────────────────────────────────────

async def read_uploaded_code(file: UploadFile) -> RawCodePayload:
    if not file.filename:
        raise HTTPException(status_code=400, detail="Missing file name")
    content = await file.read()
    if not content:
        raise HTTPException(status_code=400, detail="Uploaded file is empty")
    try:
        raw_code = content.decode("utf-8")
    except UnicodeDecodeError:
        raise HTTPException(status_code=400, detail="File must be UTF-8 encoded text")
    return RawCodePayload(
        originalName=file.filename,
        language=detect_language(file.filename),
        size=len(content),
        rawCode=raw_code,
    )


# ── Hard override check ───────────────────────────────────────────────────────

def _is_hard_vulnerable(signals: set[str]) -> bool:
    """
    Return True if the signal combination ALWAYS means vulnerable,
    regardless of what the ML model scored.

    This prevents a high concentration of SAFE_EXEC tokens in a long
    file from diluting the score of a single deeply buried vulnerable
    function.
    """
    for combo in ALWAYS_VULNERABLE_COMBOS:
        if combo.issubset(signals):
            return True
    return False


def _rule_score(signals: set[str]) -> float:
    """
    Compute a rule-based risk score from detected signals.
    Used when the ML model is not loaded, and also as a floor
    when the ML score disagrees with strong rule signals.
    """
    if _is_hard_vulnerable(signals):
        return 0.90

    n_high = sum(1 for s in signals if s in HIGH_SIGNALS)
    has_unsafe = "UNSAFE_EXEC" in signals
    has_sql    = "SQL_STRING" in signals
    has_safe   = "SAFE_EXEC"  in signals

    if n_high >= 2:
        return 0.88
    if n_high == 1:
        return 0.75 if has_unsafe else 0.72
    if has_unsafe and has_sql:
        return 0.62
    if has_safe and not has_sql:
        return 0.08
    return 0.25


def _fuse_scores(ml_score: float | None, rule_score: float, signals: set[str]) -> float:
    """
    Combine ML score and rule-based score.

    Policy:
    1. If a HARD_VULNERABLE combo is present → always 0.90+
    2. If ML model is not loaded → use rule score only
    3. Otherwise → take the MAX of (ml_score, rule_score)
       This ensures a single dangerous function in a long safe file
       is not hidden by the file-level ML average.
    """
    if _is_hard_vulnerable(signals):
        return max(0.90, ml_score if ml_score is not None else 0.0)

    if ml_score is None:
        return rule_score

    return max(ml_score, rule_score)


# ── Chunk-level analysis ──────────────────────────────────────────────────────

def _analyse_chunk(
    code: str,
    chunk_name: str,
) -> dict:
    """
    Run preprocessing + ML inference on a single code chunk.
    Returns a dict with signals, rule_score, ml_score, fused_score.
    """
    cleaned  = clean_code(code)
    tokens   = tokenize_code(cleaned)
    norm     = normalize_tokens(tokens)
    vec      = vectorize_tokens(norm, VOCABULARY)
    signals  = set(norm)

    ml_result = run_inference(vec["tokenIds"])
    ml_score  = ml_result["riskScore"] if ml_result else None

    r_score = _rule_score(signals)
    f_score = _fuse_scores(ml_score, r_score, signals)

    return {
        "chunkName":  chunk_name,
        "signals":    signals,
        "norm":       norm,
        "tokenIds":   vec["tokenIds"],
        "mlScore":    ml_score,
        "ruleScore":  r_score,
        "fusedScore": f_score,
        "seqLen":     len(norm),
    }


# ── Pattern builder ───────────────────────────────────────────────────────────

def _build_patterns(signals: set[str], worst_chunk: str) -> list[SuspiciousPattern]:
    patterns: list[SuspiciousPattern] = []

    if "FSTRING_SQL" in signals:
        patterns.append(SuspiciousPattern(
            pattern="FSTRING_SQL",
            description=(
                f"F-string SQL injection in '{worst_chunk}': "
                "user variable embedded directly in SQL via f\"...{{var}}...\""
            ),
            severity="HIGH",
        ))
    if "SQL_CONCAT" in signals:
        patterns.append(SuspiciousPattern(
            pattern="SQL_CONCAT",
            description=(
                f"SQL string concatenation in '{worst_chunk}': "
                "SQL_STRING + variable — user input merged into query via + operator"
            ),
            severity="HIGH",
        ))
    if "UNSAFE_EXEC" in signals:
        patterns.append(SuspiciousPattern(
            pattern="UNSAFE_EXEC",
            description=(
                f"Unsafe execute() in '{worst_chunk}': "
                "cursor.execute(query) called with a single argument — no parameter tuple"
            ),
            severity="HIGH" if patterns else "MEDIUM",
        ))

    return patterns


# ── Model 1: Detection ────────────────────────────────────────────────────────

def _build_detection(
    raw_code: str,
    language: str,
    # These are the file-level norm/vec passed in from process_uploaded_code
    # for backward compat with history items that don't store chunk data
    file_norm: list[str] | None = None,
    file_token_ids: list[int] | None = None,
) -> ScanDetectionInfo:
    """
    Chunk-level detection with max-pool aggregation.

    Steps:
    1. Split code into function/method chunks
    2. Analyse each chunk independently (preprocessing + ML)
    3. Take the chunk with the highest fused score (max-pool)
    4. Apply hard override: if ANY chunk has HARD_VULNERABLE signals → VULNERABLE
    5. Build the final verdict from the worst chunk's score
    """
    chunks = split_into_chunks(raw_code, language)

    # Analyse every chunk
    results = []
    for chunk_name, chunk_code in chunks:
        r = _analyse_chunk(chunk_code, chunk_name)
        results.append(r)

    # Max-pool: pick the chunk with the highest fused score
    worst = max(results, key=lambda r: r["fusedScore"])

    # Aggregate all signals across all chunks (union)
    all_signals: set[str] = set()
    for r in results:
        all_signals |= r["signals"]

    # Hard override: if HARD_VULNERABLE combo appears anywhere in the file
    hard_vuln = _is_hard_vulnerable(all_signals)
    final_score = worst["fusedScore"]
    if hard_vuln:
        final_score = max(final_score, 0.90)

    model_loaded = worst["mlScore"] is not None

    # Determine label
    if final_score >= 0.70:
        label = "VULNERABLE"
    elif final_score >= 0.45:
        label = "SUSPICIOUS"
    else:
        label = "SAFE"

    # Build patterns from the worst chunk's signals
    worst_signals = worst["signals"]
    patterns = _build_patterns(worst_signals, worst["chunkName"])

    # Build explanation
    vuln_type = None
    if label == "VULNERABLE":
        vuln_type = "SQL Injection"
        if patterns:
            pnames = " + ".join(p.pattern for p in patterns)
            chunk_info = (
                f" (found in function '{worst['chunkName']}')"
                if worst["chunkName"] != "__file__"
                else ""
            )
            explanation = (
                f"SQL injection pattern detected{chunk_info}: {pnames}. "
                f"Risk score: {final_score:.0%}. "
                f"File analysed in {len(results)} chunk(s) — worst chunk scored {worst['fusedScore']:.0%}."
            )
        else:
            explanation = f"High risk score ({final_score:.0%}) from ML model."

    elif label == "SUSPICIOUS":
        vuln_type = "Possible SQL Injection"
        explanation = (
            f"Suspicious patterns detected (score {final_score:.0%}). "
            f"Manual review recommended."
        )
    else:
        if "SAFE_EXEC" in all_signals:
            explanation = (
                f"Parameterized queries detected throughout the file (SAFE_EXEC signals). "
                f"Risk score: {final_score:.0%}."
            )
        else:
            explanation = f"No SQL injection patterns detected. Risk score: {final_score:.0%}."

    return ScanDetectionInfo(
        riskScore=round(final_score, 4),
        label=label,
        confidence=round(final_score, 4),
        vulnerabilityType=vuln_type,
        explanation=explanation,
        suspiciousPatterns=patterns,
        modelLoaded=model_loaded,
    )


# ── Main scan pipeline ────────────────────────────────────────────────────────

async def process_uploaded_code(file: UploadFile, current_user: dict) -> ScanResponse:
    """
    Model 1 pipeline:
      Upload → file-level preprocessing (for display) + chunk-level detection
    Fix is NOT generated here — only when user explicitly requests it.
    """
    raw_payload = await read_uploaded_code(file)

    # File-level preprocessing (for display in frontend)
    cleaned_code      = clean_code(raw_payload.rawCode)
    tokens            = tokenize_code(cleaned_code)
    normalized_tokens = normalize_tokens(tokens)
    vectorized_result = vectorize_tokens(normalized_tokens, VOCABULARY)

    # Chunk-level detection (the actual verdict)
    detection = _build_detection(
        raw_code=raw_payload.rawCode,
        language=raw_payload.language,
    )

    # Audit log
    scan_id = await log_audit_event(
        action="code_scanned",
        actor_user_id=current_user["id"],
        details={
            "originalName":    raw_payload.originalName,
            "language":        raw_payload.language,
            "size":            raw_payload.size,
            "sequenceLength":  len(normalized_tokens),
            "rawCode":         raw_payload.rawCode,
            "cleanedCode":     cleaned_code,
            "tokens":          tokens,
            "normalizedTokens": normalized_tokens,
            "detection":       detection.model_dump(),
        },
    )

    return ScanResponse(
        scanId=scan_id,
        file=ScanFileInfo(
            originalName=raw_payload.originalName,
            language=raw_payload.language,
            size=raw_payload.size,
        ),
        preprocessing=ScanPreprocessingInfo(
            cleanedCode=cleaned_code,
            tokens=tokens,
            normalizedTokens=normalized_tokens,
            sequenceLength=len(normalized_tokens),
        ),
        vectorization=ScanVectorizationInfo(
            tokenIds=vectorized_result["tokenIds"],
            paddedLength=vectorized_result["paddedLength"],
            truncated=vectorized_result["truncated"],
        ),
        detection=detection,
    )


# ── Model 2: Generate fix (user-triggered only) ───────────────────────────────

async def generate_fix_for_scan(
    scan_id: str,
    current_user: dict,
) -> GenerateFixResponse:
    """
    Model 2 — triggered only when user clicks 'Generate Fix'.
    Uses the fix engine on the raw code stored at scan time.
    """
    audit_logs = get_audit_logs_collection()

    try:
        doc = await audit_logs.find_one(
            {
                "_id": ObjectId(scan_id),
                "action": "code_scanned",
                "actorUserId": current_user["id"],
            }
        )
    except Exception:
        raise HTTPException(status_code=404, detail="Scan not found")

    if not doc:
        raise HTTPException(status_code=404, detail="Scan not found")

    details  = doc.get("details", {})
    raw_code = details.get("rawCode", "")
    language = details.get("language", "python")
    normalized_tokens = details.get("normalizedTokens", [])

    if not raw_code:
        raise HTTPException(
            status_code=422,
            detail="Cannot generate fix: original code not stored for this scan.",
        )

    # For the fix engine, find the worst chunk in the file
    chunks = split_into_chunks(raw_code, language)
    best_fix = None

    for chunk_name, chunk_code in chunks:
        norm = normalize_tokens(tokenize_code(clean_code(chunk_code)))
        fix_result = generate_fix(chunk_code, language, norm)
        if fix_result is not None:
            best_fix = fix_result
            break   # take the first (worst) chunk that has a vulnerability

    # Fallback to file-level fix engine
    if best_fix is None:
        best_fix = generate_fix(raw_code, language, normalized_tokens)

    if best_fix is None:
        raise HTTPException(
            status_code=422,
            detail="No SQL injection pattern detected — no fix can be generated.",
        )

    return GenerateFixResponse(
        vulnerabilityType=best_fix.vulnerability_type,
        fixType=best_fix.fix_type,
        fixStrategy=best_fix.fix_strategy,
        explanation=best_fix.explanation,
        fixedCode=best_fix.fixed_code,
    )


# ── History ───────────────────────────────────────────────────────────────────

async def get_user_scan_history(
    current_user: dict,
    limit: int = 50,
) -> ScanHistoryListResponse:
    audit_logs = get_audit_logs_collection()
    docs = (
        await audit_logs.find(
            {"action": "code_scanned", "actorUserId": current_user["id"]}
        )
        .sort("timestamp", -1)
        .limit(limit)
        .to_list(length=limit)
    )

    history = []
    for doc in docs:
        details = doc.get("details", {})
        saved_detection = details.get("detection", {})
        detection_label = saved_detection.get("label") if saved_detection else None
        history.append(
            ScanHistoryItemResponse(
                id=str(doc["_id"]),
                originalName=details.get("originalName", "unknown"),
                language=details.get("language", "unknown"),
                size=details.get("size", 0),
                sequenceLength=details.get("sequenceLength", 0),
                timestamp=doc.get("timestamp"),
                detectionLabel=detection_label,
            )
        )
    return ScanHistoryListResponse(history=history, count=len(history))


async def get_scan_history_item(
    history_id: str,
    current_user: dict,
) -> ScanResponse:
    audit_logs = get_audit_logs_collection()

    try:
        doc = await audit_logs.find_one(
            {
                "_id": ObjectId(history_id),
                "action": "code_scanned",
                "actorUserId": current_user["id"],
            }
        )
    except Exception:
        raise HTTPException(status_code=404, detail="History item not found")

    if not doc:
        raise HTTPException(status_code=404, detail="History item not found")

    details           = doc.get("details", {})
    normalized_tokens = details.get("normalizedTokens", [])
    raw_code          = details.get("rawCode", "")
    language          = details.get("language", "python")

    vectorized_result = vectorize_tokens(normalized_tokens, VOCABULARY)

    # Restore saved detection; re-run only if missing
    saved_detection = details.get("detection")
    if saved_detection:
        detection = ScanDetectionInfo(**saved_detection)
    else:
        detection = _build_detection(raw_code=raw_code, language=language)

    return ScanResponse(
        scanId=history_id,
        file=ScanFileInfo(
            originalName=details.get("originalName", "unknown"),
            language=details.get("language", "unknown"),
            size=details.get("size", 0),
        ),
        preprocessing=ScanPreprocessingInfo(
            cleanedCode=details.get("cleanedCode", ""),
            tokens=details.get("tokens", []),
            normalizedTokens=normalized_tokens,
            sequenceLength=details.get("sequenceLength", 0),
        ),
        vectorization=ScanVectorizationInfo(
            tokenIds=vectorized_result["tokenIds"],
            paddedLength=vectorized_result["paddedLength"],
            truncated=vectorized_result["truncated"],
        ),
        detection=detection,
    )
