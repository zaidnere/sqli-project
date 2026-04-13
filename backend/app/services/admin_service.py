from app.schemas.scan import AdminDashboardSummaryResponse


async def get_admin_dashboard_summary(users_collection, audit_logs_collection):
    total_users = await users_collection.count_documents({})
    total_scans = await audit_logs_collection.count_documents({"action": "code_scanned"})
    total_successful_logins = await audit_logs_collection.count_documents({"action": "user_logged_in"})
    total_failed_logins = await audit_logs_collection.count_documents({"action": "login_failed"})
    total_audit_events = await audit_logs_collection.count_documents({})

    return AdminDashboardSummaryResponse(
        totalUsers=total_users,
        totalScans=total_scans,
        totalSuccessfulLogins=total_successful_logins,
        totalFailedLogins=total_failed_logins,
        totalAuditEvents=total_audit_events,
    )