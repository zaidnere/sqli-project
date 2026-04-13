from datetime import datetime
from typing import Optional
from pydantic import BaseModel, EmailStr


class UserRegisterRequest(BaseModel):
    email: EmailStr
    password: str
    fullName: Optional[str] = None


class UserLoginRequest(BaseModel):
    email: EmailStr
    password: str


class UserResponse(BaseModel):
    id: str
    email: EmailStr
    fullName: Optional[str] = None
    role: str
    createdAt: datetime
    updatedAt: datetime
    isActive: bool


class LoginResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"