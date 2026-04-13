from pathlib import Path

from bson import ObjectId
from fastapi import HTTPException, UploadFile

from app.db.database import get_audit_logs_collection
from app.preprocessing.code_cleaner import clean_code
from app.preprocessing.tokenizer import tokenize_code
from app.preprocessing.normalizer import normalize_tokens
from app.preprocessing.model_input_builder import build_model_input
from app.schemas.scan import (
    CleanCodePayload,
    NormalizedCodePayload,
    RawCodePayload,
    ScanFileInfo,
    ScanHistoryItemResponse,
    ScanHistoryListResponse,
    ScanPreprocessingInfo,
    ScanResponse,
    TokenizedCodePayload,
)
from app.services.audit_log_service import log_audit_event


ALLOWED_EXTENSIONS = {
    ".py": "python",
    ".js": "javascript",
    ".php": "php",
    ".java": "java",
}


def detect_language(filename: str) -> str:
    suffix = Path(filename).suffix.lower()
    if suffix not in ALLOWED_EXTENSIONS:
        raise HTTPException(
            status_code=400,
            detail="Unsupported file type. Allowed: .py, .js, .php, .java",
        )
    return ALLOWED_EXTENSIONS[suffix]


async def read_uploaded_code(file: UploadFile) -> RawCodePayload:
    if not file.filename:
        raise HTTPException(status_code=400, detail="Missing file name")

    language = detect_language(file.filename)

    content = await file.read()
    if not content:
        raise HTTPException(status_code=400, detail="Uploaded file is empty")

    try:
        raw_code = content.decode("utf-8")
    except UnicodeDecodeError:
        raise HTTPException(status_code=400, detail="File must be UTF-8 text")

    return RawCodePayload(
        originalName=file.filename,
        language=language,
        size=len(content),
        rawCode=raw_code,
    )


async def process_uploaded_code(file: UploadFile, current_user: dict) -> ScanResponse:
    raw_payload = await read_uploaded_code(file)

    cleaned_code = clean_code(raw_payload.rawCode)
    clean_payload = CleanCodePayload(
        originalName=raw_payload.originalName,
        language=raw_payload.language,
        size=raw_payload.size,
        cleanCode=cleaned_code,
    )

    tokens = tokenize_code(clean_payload.cleanCode)
    tokenized_payload = TokenizedCodePayload(
        originalName=clean_payload.originalName,
        language=clean_payload.language,
        tokens=tokens,
    )

    normalized_tokens = normalize_tokens(tokenized_payload.tokens)
    normalized_payload = NormalizedCodePayload(
        originalName=tokenized_payload.originalName,
        language=tokenized_payload.language,
        normalizedTokens=normalized_tokens,
    )

    model_input = build_model_input(
        language=normalized_payload.language,
        normalized_tokens=normalized_payload.normalizedTokens,
    )

    scan_response = ScanResponse(
        file=ScanFileInfo(
            originalName=raw_payload.originalName,
            language=raw_payload.language,
            size=raw_payload.size,
        ),
        preprocessing=ScanPreprocessingInfo(
            cleanedCode=clean_payload.cleanCode,
            tokens=tokenized_payload.tokens,
            normalizedTokens=normalized_payload.normalizedTokens,
            sequenceLength=model_input.length,
        ),
    )

    await log_audit_event(
        action="code_scanned",
        actor_user_id=current_user["id"],
        details={
            "originalName": raw_payload.originalName,
            "language": raw_payload.language,
            "size": raw_payload.size,
            "sequenceLength": model_input.length,
            "cleanedCode": clean_payload.cleanCode,
            "tokens": tokenized_payload.tokens,
            "normalizedTokens": normalized_payload.normalizedTokens,
        },
    )

    return scan_response


async def get_user_scan_history(current_user: dict, limit: int = 50) -> ScanHistoryListResponse:
    audit_logs = get_audit_logs_collection()

    docs = (
        await audit_logs.find(
            {
                "action": "code_scanned",
                "actorUserId": current_user["id"],
            }
        )
        .sort("timestamp", -1)
        .limit(limit)
        .to_list(length=limit)
    )

    history = []
    for doc in docs:
        details = doc.get("details", {})

        history.append(
            ScanHistoryItemResponse(
                id=str(doc["_id"]),
                originalName=details.get("originalName", "unknown"),
                language=details.get("language", "unknown"),
                size=details.get("size", 0),
                sequenceLength=details.get("sequenceLength", 0),
                timestamp=doc.get("timestamp"),
            )
        )

    return ScanHistoryListResponse(
        history=history,
        count=len(history),
    )


async def get_scan_history_item(history_id: str, current_user: dict) -> ScanResponse:
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

    details = doc.get("details", {})

    return ScanResponse(
        file=ScanFileInfo(
            originalName=details.get("originalName", "unknown"),
            language=details.get("language", "unknown"),
            size=details.get("size", 0),
        ),
        preprocessing=ScanPreprocessingInfo(
            cleanedCode=details.get("cleanedCode", ""),
            tokens=details.get("tokens", []),
            normalizedTokens=details.get("normalizedTokens", []),
            sequenceLength=details.get("sequenceLength", 0),
        ),
    )