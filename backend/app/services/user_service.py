from datetime import datetime, timezone
from bson import ObjectId
from fastapi import HTTPException
from pymongo.errors import DuplicateKeyError

from app.core.security import hash_password, verify_password, create_access_token
from app.db.database import get_users_collection
from app.services.audit_log_service import log_audit_event


def serialize_user(user: dict):
    return {
        "id": str(user["_id"]),
        "email": user["email"],
        "fullName": user.get("fullName"),
        "role": user["role"],
        "createdAt": user["createdAt"],
        "updatedAt": user["updatedAt"],
        "isActive": user["isActive"],
    }


async def create_user(email: str, password: str, full_name: str | None):
    users = get_users_collection()
    now = datetime.now(timezone.utc)

    user_doc = {
        "email": email,
        "passwordHash": hash_password(password),
        "fullName": full_name,
        "role": "user",
        "createdAt": now,
        "updatedAt": now,
        "isActive": True,
    }

    try:
        result = await users.insert_one(user_doc)
    except DuplicateKeyError:
        raise HTTPException(status_code=400, detail="User already exists")

    created_user = await users.find_one({"_id": result.inserted_id})
    serialized_user = serialize_user(created_user)

    await log_audit_event(
        action="user_registered",
        actor_user_id=serialized_user["id"],
        details={
            "email": serialized_user["email"],
        },
    )

    return serialized_user


async def login_user(email: str, password: str):
    users = get_users_collection()

    user = await users.find_one({"email": email})
    if not user:
        await log_audit_event(
            action="login_failed",
            actor_user_id=None,
            details={"email": email, "reason": "user_not_found"},
        )
        raise HTTPException(status_code=401, detail="Invalid email or password")

    if not user.get("isActive", True):
        await log_audit_event(
            action="login_failed",
            actor_user_id=str(user["_id"]),
            details={"email": email, "reason": "user_inactive"},
        )
        raise HTTPException(status_code=403, detail="User is inactive")

    if not verify_password(password, user["passwordHash"]):
        await log_audit_event(
            action="login_failed",
            actor_user_id=str(user["_id"]),
            details={"email": email, "reason": "invalid_password"},
        )
        raise HTTPException(status_code=401, detail="Invalid email or password")

    token = create_access_token(
        {
            "sub": str(user["_id"]),
            "email": user["email"],
            "role": user.get("role", "user"),
        }
    )

    await log_audit_event(
        action="user_logged_in",
        actor_user_id=str(user["_id"]),
        details={"email": user["email"]},
    )

    return {
        "access_token": token,
        "token_type": "bearer",
    }


async def get_user_by_id(user_id: str):
    users = get_users_collection()

    try:
        user = await users.find_one({"_id": ObjectId(user_id)})
    except Exception:
        return None

    if not user:
        return None

    return serialize_user(user)