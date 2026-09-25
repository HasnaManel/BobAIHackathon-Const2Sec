"""Pydantic request and response models for SecureGate.

All response models deliberately exclude hashed_password.
"""

from pydantic import BaseModel, EmailStr, Field


# ---------------------------------------------------------------------------
# Auth
# ---------------------------------------------------------------------------

class UserRegister(BaseModel):
    username: str = Field(..., min_length=3, max_length=32)
    email: EmailStr
    password: str = Field(..., min_length=8, max_length=128)


class UserLogin(BaseModel):
    username: str
    password: str


class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"


# ---------------------------------------------------------------------------
# Users
# ---------------------------------------------------------------------------

class UserProfile(BaseModel):
    id: int
    username: str
    email: str
    is_admin: bool
    created_at: str


class UserEmailUpdate(BaseModel):
    email: EmailStr


# ---------------------------------------------------------------------------
# Products
# ---------------------------------------------------------------------------

class ProductCreate(BaseModel):
    name: str = Field(..., min_length=1, max_length=128)
    description: str = Field(default="", max_length=1024)
    price: float = Field(..., gt=0)


class ProductResponse(BaseModel):
    id: int
    name: str
    description: str
    price: float
    owner_id: int
