from fastapi import APIRouter, Depends, File, Query, UploadFile

from app.api.deps import get_current_user
from app.schemas.scan import ScanHistoryListResponse, ScanResponse
from app.services.scan_service import (
    process_uploaded_code,
    get_user_scan_history,
    get_scan_history_item,
)

router = APIRouter(prefix="/api/scans", tags=["Scans"])


@router.post("/upload-and-scan", response_model=ScanResponse)
async def upload_and_scan(
    file: UploadFile = File(...),
    current_user=Depends(get_current_user),
):
    return await process_uploaded_code(file, current_user)


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