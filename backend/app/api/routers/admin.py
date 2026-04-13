from fastapi import APIRouter, Depends

from app.api.deps import require_admin
from app.db.database import get_audit_logs_collection, get_users_collection
from app.services.admin_service import get_admin_dashboard_summary
from app.schemas.scan import AdminDashboardSummaryResponse

router = APIRouter(prefix="/api/admin", tags=["Admin"])


@router.get("/dashboard-summary", response_model=AdminDashboardSummaryResponse)
async def read_admin_dashboard_summary(
    current_admin=Depends(require_admin),
):
    users_collection = get_users_collection()
    audit_logs_collection = get_audit_logs_collection()

    return await get_admin_dashboard_summary(
        users_collection=users_collection,
        audit_logs_collection=audit_logs_collection,
    )