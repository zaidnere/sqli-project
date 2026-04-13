from datetime import datetime, timezone

from app.db.database import get_audit_logs_collection


async def log_audit_event(
    action: str,
    actor_user_id: str | None = None,
    details: dict | None = None,
):
    audit_logs = get_audit_logs_collection()

    log_doc = {
        "actorUserId": actor_user_id,
        "action": action,
        "details": details or {},
        "timestamp": datetime.now(timezone.utc),
    }

    await audit_logs.insert_one(log_doc)