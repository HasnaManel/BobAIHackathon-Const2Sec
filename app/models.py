"""Pydantic request and response models for SecureGate.

All response models deliberately exclude hashed_password.
"""

from pydantic import BaseModel, EmailStr, Field, field_validator


# ---------------------------------------------------------------------------
# Auth
# ---------------------------------------------------------------------------

class UserRegister(BaseModel):
    username: str = Field(..., min_length=3, max_length=32)
    email: EmailStr
    password: str = Field(..., min_length=8, max_length=128)

    @field_validator("password")
    @classmethod
    def password_complexity(cls, v: str) -> str:
        """FIND-002: enforce at least one uppercase, one lowercase, and one digit."""
        if not any(c.isupper() for c in v):
            raise ValueError("Password must contain at least one uppercase letter.")
        if not any(c.islower() for c in v):
            raise ValueError("Password must contain at least one lowercase letter.")
        if not any(c.isdigit() for c in v):
            raise ValueError("Password must contain at least one digit.")
        return v


class UserLogin(BaseModel):
    # FIND-004 fix: add length constraints to prevent oversized-input DoS and
    # to match the constraints already present on UserRegister.
    username: str = Field(..., min_length=1, max_length=64)
    password: str = Field(..., min_length=1, max_length=128)


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
