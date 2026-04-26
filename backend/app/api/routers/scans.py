from fastapi import APIRouter, Depends, File, Path, Query, UploadFile

from app.api.deps import get_current_user
from app.model.inference import model_is_loaded, WEIGHTS_PATH
from app.schemas.scan import (
    GenerateFixResponse,
    ModelStatusResponse,
    ScanHistoryListResponse,
    ScanResponse,
)
from app.services.scan_service import (
    generate_fix_for_scan,
    get_scan_history_item,
    get_user_scan_history,
    process_uploaded_code,
)

router = APIRouter(prefix="/api/scans", tags=["Scans"])


# ── Model status ──────────────────────────────────────────────────────────────

@router.get("/model-status", response_model=ModelStatusResponse)
async def read_model_status():
    """Check whether the trained Model 1 weights are loaded."""
    loaded = model_is_loaded()
    return ModelStatusResponse(
        modelLoaded=loaded,
        message=(
            "Detection model is ready."
            if loaded
            else (
                "Model weights not found. "
                "Train Model 1 in Colab and place sqli_model.npz in "
                "backend/app/model/weights/"
            )
        ),
        weightsPath=WEIGHTS_PATH,
    )


# ── Model 1: scan ─────────────────────────────────────────────────────────────

@router.post("/upload-and-scan", response_model=ScanResponse)
async def upload_and_scan(
    file: UploadFile = File(...),
    current_user=Depends(get_current_user),
):
    """
    Upload a source code file and run Model 1 (detection).
    Returns detection result only — no fix is generated automatically.
    """
    return await process_uploaded_code(file, current_user)


# ── Model 2: generate fix (user-triggered) ────────────────────────────────────

@router.post("/generate-fix/{scan_id}", response_model=GenerateFixResponse)
async def request_fix(
    scan_id: str = Path(..., description="The scanId returned by upload-and-scan"),
    current_user=Depends(get_current_user),
):
    """
    Trigger Model 2 (fix recommendation) for a previously scanned file.
    This endpoint is called ONLY when the user explicitly clicks 'Generate Fix'.
    """
    return await generate_fix_for_scan(scan_id, current_user)


# ── History ───────────────────────────────────────────────────────────────────

@router.get("/history", response_model=ScanHistoryListResponse)
async def read_scan_history(
    limit: int = Query(default=50, ge=1, le=200),
    current_user=Depends(get_current_user),
):
    return await get_user_scan_history(current_user=current_user, limit=limit)


@router.get("/history/{history_id}", response_model=ScanResponse)
async def read_scan_history_item(
    history_id: str,
    current_user=Depends(get_current_user),
):
    return await get_scan_history_item(history_id=history_id, current_user=current_user)
