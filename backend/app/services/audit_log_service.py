from datetime import datetime, timezone

from app.db.database import get_audit_logs_collection


async def log_audit_event(
    action: str,
    actor_user_id: str | None = None,
    details: dict | None = None,
) -> str:
    """Insert an audit log entry and return its MongoDB ObjectId as string."""
    audit_logs = get_audit_logs_collection()

    log_doc = {
        "actorUserId": actor_user_id,
        "action": action,
        "details": details or {},
        "timestamp": datetime.now(timezone.utc),
    }

    result = await audit_logs.insert_one(log_doc)
    return str(result.inserted_id)
