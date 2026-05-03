"""
Scan service — two-model pipeline.

Model 1 (Detection): runs on every upload, uses chunk-level max-pooling.
Model 2 (Fix):       runs only when user clicks "Generate Fix".

Architecture decision — rule-vs-ML (Gap B):
─────────────────────────────────────────────
This file implements an ML-primary verdict with a deterministic rule layer
as an auxiliary explainability + safety-net component. In short:

  - The trained CNN+BiLSTM model is the primary classifier.
  - Rule signals (FSTRING_SQL, SQL_CONCAT, etc.) are emitted by the
    preprocessing step and feed BOTH the model (as input tokens) AND a
    parallel deterministic score, so the user sees *why* a chunk was flagged.
  - Fusion (`_fuse_scores`) lets ML override rules when ML is very confident,
    and lets rules win on patterns where the model is uncertain.
  - When the ML model is unavailable, the rule layer alone produces a
    degraded but functional verdict.

Every chunk in the response includes a `verdictSource` field exposing which
layer drove the decision. See backend/docs/ARCHITECTURE.md for full details,
worked examples, and the academic-defense framing.
"""
from pathlib import Path

from bson import ObjectId
from fastapi import HTTPException, UploadFile

from app.core.constants import ALLOWED_EXTENSIONS
from app.db.database import get_audit_logs_collection
from app.preprocessing.code_cleaner import clean_code
from app.preprocessing.tokenizer import tokenize_code
from app.preprocessing.normalizer import normalize_tokens, extract_safe_returning_funcs
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
HIGH_SIGNALS = {"FSTRING_SQL", "SQL_CONCAT", "FSTRING_SQL_RAW"}

# Signals that are dangerous when combined with a SQL context
MEDIUM_SIGNALS = {"UNSAFE_EXEC"}

# Signals that indicate parameterized / safe usage
SAFE_SIGNALS = {"SAFE_EXEC", "SAFE_PLACEHOLDER_LIST", "SAFE_NUMERIC_VAR"}

# These combos are ALWAYS vulnerable — hard override ignores the ML score
ALWAYS_VULNERABLE_COMBOS = [
    {"SQL_CONCAT", "UNSAFE_EXEC"},        # concat + unsafe exec
    {"FSTRING_SQL", "UNSAFE_EXEC"},       # f-string injection + unsafe exec
    {"FSTRING_SQL"},                      # f-string SQL alone is enough
    {"FSTRING_SQL_RAW"},                  # f-string with RAW interpolated var (always)
    {"SQL_CONCAT"},                       # concat alone is enough
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
    # ── Gap-A v2 safe-overrides (ordered: most specific first) ──────────────
    # FSTRING_SQL_RAW is non-negotiable — always vulnerable, even if other
    # safe signals are present in the same chunk.
    if "FSTRING_SQL_RAW" in signals:
        return 0.90

    # SAFE_NUMERIC_VAR + FSTRING_SQL (no concat) → safe LIMIT/OFFSET pattern
    if (
        "SAFE_NUMERIC_VAR" in signals
        and "FSTRING_SQL" in signals
        and "SQL_CONCAT" not in signals
    ):
        return 0.08

    # SAFE_PLACEHOLDER_LIST + SAFE_EXEC → safe IN(?,?,?) pattern
    if (
        "SAFE_PLACEHOLDER_LIST" in signals
        and "SAFE_EXEC" in signals
        and "SQL_CONCAT" not in signals
    ):
        return 0.08

    # WHITELIST_VAR marks a strict-allowlist-validated identifier. When NO
    # SQL_CONCAT (raw-input concat is real injection) AND NO FSTRING_SQL_RAW
    # (raw var interpolated despite whitelist context — already handled
    # above), the f-string is safe by construction.
    if "WHITELIST_VAR" in signals and "SQL_CONCAT" not in signals:
        return 0.10

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


def _fuse_scores(
    ml_score: float | None,
    rule_score: float,
    signals: set[str],
) -> tuple[float, str]:
    """
    Combine ML score and rule-based score.

    Returns (fused_score, source_tag). The source_tag is exposed in the API
    response as `verdictSource` so the frontend can show which layer drove
    the verdict. Possible values:

        "rule_safety_net"     — ML model unavailable; rule layer is the verdict.
        "ml_overrides_rule"   — ML strongly disagreed with rule and won
                                (whitelist-validated f-string pattern).
        "ml"                  — ML score won and rule was neutral or agreed.
        "ml+rule"             — ML and rule both flagged the chunk; max(ml, rule).
        "rule"                — Rule beat ML (e.g. ML was confused on a
                                builder-pattern chunk that the rule clearly
                                marked dangerous via SQL_CONCAT).

    Policy (ML-primary, rule = soft prior, with calibrated escape clauses):

    1. If ML model is NOT loaded → fall back to deterministic rule score
       → source = "rule_safety_net".

    2. ML loaded:

       a. CONFIDENT-SAFE ESCAPE: ml_score < 0.05 AND no high-confidence rule
          signals → trust ML. Obvious-safe cases (parameterised, ORM, no SQL).
          → source = "ml".

       b. VALIDATED F-STRING OVERRIDE: ml_score < 0.05 AND FSTRING_SQL is
          present BUT SQL_CONCAT is NOT → trust ML. The "validated dynamic
          SQL" pattern: f-string built from whitelist-validated values.
          → source = "ml_overrides_rule".

          We require the absence of SQL_CONCAT because string concatenation
          (`"SELECT ... " + var`) is almost always genuine injection.

       c. OTHERWISE → max(ml_score, rule_score). Conservative default.
          - If the winner is rule and rule >= ml + 0.10 → source = "rule".
          - If both are roughly aligned (within 0.10) → source = "ml+rule".
          - If ml is the winner by a clear margin → source = "ml".

    The hard-override list (ALWAYS_VULNERABLE_COMBOS) is kept ONLY as a
    failsafe path when ML is unavailable.
    """
    if ml_score is None:
        if _is_hard_vulnerable(signals):
            return max(0.90, rule_score), "rule_safety_net"
        return rule_score, "rule_safety_net"

    has_fstring = "FSTRING_SQL" in signals
    has_fstring_raw = "FSTRING_SQL_RAW" in signals
    has_concat  = "SQL_CONCAT"  in signals
    has_whitelist = "WHITELIST_VAR" in signals

    # 0. FSTRING_SQL_RAW is non-negotiable — raw var interpolated despite
    # whitelist context. Real injection. Rule wins regardless of ML.
    if has_fstring_raw:
        return max(rule_score, 0.90), "rule"

    # 2a. Confident-safe, no dangerous rule signal at all → ML wins outright
    if ml_score < 0.05 and not has_fstring and not has_concat:
        return ml_score, "ml"

    # 2b. Whitelist-validated f-string: ML strongly says safe AND a strict
    # allowlist marker is present AND no concat. Without WHITELIST_VAR we
    # never trust ML over rule on FSTRING_SQL — raw f-string is real injection.
    if (ml_score < 0.05 and has_fstring and has_whitelist and not has_concat):
        return ml_score, "ml_overrides_rule"

    # 2b-bis. Strong-whitelist override: WHITELIST_VAR / SAFE_PLACEHOLDER_LIST
    # / SAFE_NUMERIC_VAR present AND no real injection signals (FSTRING_SQL_RAW,
    # SQL_CONCAT) → trust the rule layer's safe verdict regardless of ML score.
    # ML weights trained before flow signals existed cannot reason about them;
    # the rule layer's deterministic flow analysis is more reliable here.
    has_safe_flow = (
        has_whitelist
        or "SAFE_PLACEHOLDER_LIST" in signals
        or "SAFE_NUMERIC_VAR" in signals
    )
    if has_safe_flow and not has_concat and rule_score < 0.30:
        return rule_score, "rule"

    # 2c. Default: either side can raise the alarm. Tag depends on which won.
    fused = max(ml_score, rule_score)
    diff  = ml_score - rule_score
    if diff >= 0.10:
        source = "ml"
    elif diff <= -0.10:
        source = "rule"
    else:
        source = "ml+rule"
    return fused, source


# ── Chunk-level analysis ──────────────────────────────────────────────────────

def _analyse_chunk(
    code: str,
    chunk_name: str,
    extra_safe_funcs: set[str] | None = None,
) -> dict:
    """
    Run preprocessing + ML inference on a single code chunk.
    Returns a dict with signals, rule_score, ml_score, fused_score.
    """
    cleaned  = clean_code(code)
    tokens   = tokenize_code(cleaned)
    norm     = normalize_tokens(tokens, extra_safe_funcs=extra_safe_funcs)
    vec      = vectorize_tokens(norm, VOCABULARY)
    signals  = set(norm)

    # Tiny chunks (e.g. empty class bodies, decorator-only stubs, single-line
    # passthrough methods) tokenise to <8 meaningful tokens. The model has a
    # noise floor on such inputs (~0.1–0.3 score range) because the embedding
    # average is ill-defined on so few tokens. Skip ML on these and use the
    # rule score alone — if there are no signals, the rule score will be a low
    # baseline (~0.25), which then can't push the file-level verdict up.
    SKIP_ML_BELOW = 8
    if len(norm) < SKIP_ML_BELOW:
        ml_score             = None
        ml_attack_type       = "NONE"
        ml_attack_type_id    = 0
        ml_attack_conf       = 0.0
        ml_attack_probs      = {}
        ml_type_head_available = False
    else:
        ml_result = run_inference(vec["tokenIds"])
        if ml_result is None:
            ml_score             = None
            ml_attack_type       = "NONE"
            ml_attack_type_id    = 0
            ml_attack_conf       = 0.0
            ml_attack_probs      = {}
            ml_type_head_available = False
        else:
            ml_score             = ml_result["riskScore"]
            ml_attack_type       = ml_result.get("attackType", "NONE")
            ml_attack_type_id    = ml_result.get("attackTypeId", 0)
            ml_attack_conf       = ml_result.get("attackTypeConfidence", 0.0)
            ml_attack_probs      = ml_result.get("attackTypeProbs", {})
            ml_type_head_available = ml_result.get("attackTypeAvailable", False)

    r_score = _rule_score(signals)
    f_score, f_source = _fuse_scores(ml_score, r_score, signals)

    return {
        "chunkName":            chunk_name,
        "signals":              signals,
        "norm":                 norm,
        "tokenIds":             vec["tokenIds"],
        "mlScore":              ml_score,
        "ruleScore":            r_score,
        "fusedScore":           f_score,
        "verdictSource":        f_source,
        "seqLen":               len(norm),
        # Gap A — attack-type prediction (per-chunk)
        "attackType":           ml_attack_type,
        "attackTypeId":         ml_attack_type_id,
        "attackTypeConfidence": ml_attack_conf,
        "attackTypeProbs":      ml_attack_probs,
        "attackTypeAvailable":  ml_type_head_available,
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

    # Compute file-level "safe-returning helper" set BEFORE chunking each
    # function. This lets a chunk recognize that its assignment
    # `safe_col, safe_dir = normalize_sort(...)` is whitelist-validated even
    # though `normalize_sort` is defined in a different chunk.
    full_tokens = tokenize_code(clean_code(raw_code))
    file_safe_funcs = extract_safe_returning_funcs(full_tokens)

    # Analyse every chunk
    results = []
    for chunk_name, chunk_code in chunks:
        r = _analyse_chunk(chunk_code, chunk_name, extra_safe_funcs=file_safe_funcs)
        results.append(r)

    # Max-pool: pick the chunk with the highest fused score
    worst = max(results, key=lambda r: r["fusedScore"])

    # Aggregate all signals across all chunks (union)
    all_signals: set[str] = set()
    for r in results:
        all_signals |= r["signals"]

    model_loaded = worst["mlScore"] is not None

    # Hard-override floor is now a FAILSAFE for the no-ML path only.
    # When the ML model is loaded, _fuse_scores() has already let ML decide,
    # including for whitelist-guarded patterns where FSTRING_SQL appears in
    # safe context. Re-applying the rule floor here would re-introduce the
    # false positives the new fusion policy is designed to eliminate.
    final_score   = worst["fusedScore"]
    verdict_source = worst["verdictSource"]
    if not model_loaded and _is_hard_vulnerable(all_signals):
        final_score = max(final_score, 0.90)
        verdict_source = "rule_safety_net"

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

    # ── Gap A — File-level attack-type aggregation ──────────────────────────────
    # Rule: among chunks classified as vulnerable (fusedScore >= 0.45), take
    # the most common predicted attack type (mode). If multiple types are tied,
    # the priority order is SECOND_ORDER > BLIND > IN_BAND (rarest-most-specific
    # first — proposal pages 4-5 highlight these as the harder cases).
    # If NO chunks are flagged vulnerable: attackType is NONE.
    #
    # In addition to ML aggregation, a deterministic rule layer based on
    # flow signals (BOOLEAN_SINK, DB_LOADED_VAR) provides a strong override
    # when ML type-head is untrained or uncertain. This fills the gap when
    # the type head's argmax is wrong but the flow signals are present.
    type_head_available = any(r["attackTypeAvailable"] for r in results)

    vuln_chunks = [r for r in results if r["fusedScore"] >= 0.45]
    if not vuln_chunks or not type_head_available:
        file_attack_type       = "NONE"
        file_attack_type_id    = 0
        file_attack_confidence = 0.0
        file_attack_probs      = {"NONE": 1.0, "IN_BAND": 0.0, "BLIND": 0.0, "SECOND_ORDER": 0.0}
    else:
        # Mode with priority tiebreak (most-specific class wins on ties)
        type_priority = {"SECOND_ORDER": 3, "BLIND": 2, "IN_BAND": 1, "NONE": 0}
        type_votes: dict[str, int] = {}
        for r in vuln_chunks:
            t = r["attackType"]
            type_votes[t] = type_votes.get(t, 0) + 1

        winner = max(
            type_votes.items(),
            key=lambda kv: (kv[1], type_priority.get(kv[0], 0)),
        )[0]
        file_attack_type    = winner
        file_attack_type_id = {"NONE": 0, "IN_BAND": 1, "BLIND": 2, "SECOND_ORDER": 3}[winner]

        winning_chunks = [r for r in vuln_chunks if r["attackType"] == winner]
        file_attack_confidence = round(
            sum(r["attackTypeConfidence"] for r in winning_chunks) / len(winning_chunks), 4
        )

        all_classes = ("NONE", "IN_BAND", "BLIND", "SECOND_ORDER")
        file_attack_probs = {}
        for cls in all_classes:
            vals = [
                r["attackTypeProbs"].get(cls, 0.0)
                for r in vuln_chunks
                if r["attackTypeProbs"]
            ]
            file_attack_probs[cls] = (
                round(sum(vals) / len(vals), 4) if vals else 0.0
            )

    # ── Rule-based attack-type override using flow signals ─────────────────────
    # When type-head argmax is uncertain (often the case until model fully
    # trains on flow signals), use deterministic flow-signal logic:
    #   BOOLEAN_SINK + dangerous SQL signal → BLIND
    #   DB_LOADED_VAR + dangerous SQL signal (no BOOLEAN_SINK) → SECOND_ORDER
    #   Other dangerous SQL → IN_BAND
    # The override applies whenever the file is VULNERABLE/SUSPICIOUS — file
    # is unsafe by ML, and we just need to label the kind of unsafe.
    if label in ("VULNERABLE", "SUSPICIOUS"):
        has_bool_sink = "BOOLEAN_SINK" in all_signals
        has_db_loaded = "DB_LOADED_VAR" in all_signals
        has_dangerous = bool(all_signals & {"FSTRING_SQL", "SQL_CONCAT", "UNSAFE_EXEC"})
        rule_attack_type = None
        if has_bool_sink and has_dangerous:
            rule_attack_type = "BLIND"
        elif has_db_loaded and has_dangerous and not has_bool_sink:
            rule_attack_type = "SECOND_ORDER"
        elif has_dangerous:
            rule_attack_type = "IN_BAND"
        if rule_attack_type is not None:
            file_attack_type = rule_attack_type
            file_attack_type_id = {"NONE": 0, "IN_BAND": 1, "BLIND": 2, "SECOND_ORDER": 3}[rule_attack_type]

    # Sanity: if VULNERABLE label but attack type came back NONE, default IN_BAND
    if label == "VULNERABLE" and file_attack_type == "NONE":
        file_attack_type    = "IN_BAND"
        file_attack_type_id = 1

    return ScanDetectionInfo(
        riskScore=round(final_score, 4),
        label=label,
        confidence=round(final_score, 4),
        vulnerabilityType=vuln_type,
        explanation=explanation,
        suspiciousPatterns=patterns,
        modelLoaded=model_loaded,
        verdictSource=verdict_source,
        # Gap A — attack-type fields
        attackType=file_attack_type,
        attackTypeConfidence=file_attack_confidence,
        attackTypeProbs=file_attack_probs,
        attackTypeAvailable=type_head_available,
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
