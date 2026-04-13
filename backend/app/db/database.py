from motor.motor_asyncio import AsyncIOMotorClient
from pymongo import ASCENDING, DESCENDING
from app.core.config import settings

client = AsyncIOMotorClient(settings.MONGODB_URL)
db = client[settings.DATABASE_NAME]


def get_users_collection():
    return db["users"]


def get_audit_logs_collection():
    return db["audit_logs"]


async def create_indexes():
    await db["users"].create_index(
        [("email", ASCENDING)],
        unique=True,
        name="unique_email_index",
    )

    await db["audit_logs"].create_index(
        [("actorUserId", ASCENDING)],
        name="audit_actor_user_index",
    )

    await db["audit_logs"].create_index(
        [("action", ASCENDING)],
        name="audit_action_index",
    )

    await db["audit_logs"].create_index(
        [("timestamp", DESCENDING)],
        name="audit_timestamp_index",
    )