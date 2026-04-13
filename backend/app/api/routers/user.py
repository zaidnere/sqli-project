from fastapi import APIRouter, Depends

from app.schemas.user import (
    UserRegisterRequest,
    UserLoginRequest,
    UserResponse,
    LoginResponse,
)
from app.services.user_service import create_user, login_user
from app.api.deps import get_current_user

router = APIRouter(prefix="/api/user", tags=["User"])


@router.post("/register", response_model=UserResponse)
async def register_user(request: UserRegisterRequest):
    return await create_user(
        request.email,
        request.password,
        request.fullName,
    )


@router.post("/login", response_model=LoginResponse)
async def login(request: UserLoginRequest):
    return await login_user(request.email, request.password)


@router.get("/me", response_model=UserResponse)
async def get_me(current_user=Depends(get_current_user)):
    return current_user