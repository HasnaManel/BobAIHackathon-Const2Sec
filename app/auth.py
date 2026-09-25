"""Authentication module — registration, login, JWT helpers, and dependencies.

Environment variables:
  APP_SIGNING_KEY       JWT signing secret (required; falls back to a weak
                        default in this INTENTIONALLY VULNERABLE version — see VULN-004).
  APP_TOKEN_MINUTES     Token lifetime in minutes (default: 30).
"""

import os
import sqlite3
from datetime import datetime, timedelta, timezone
from typing import Annotated

import bcrypt
import jwt
from fastapi import APIRouter, Depends, HTTPException, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

from app.database import get_db
from app.models import TokenResponse, UserLogin, UserProfile, UserRegister

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

# VULN-004 (intentional): falls back to a weak hardcoded default instead of
# raising an error at startup when APP_SIGNING_KEY is not set.
_SIGNING_KEY: str = os.environ.get("APP_SIGNING_KEY", "changeme")
_ALGORITHM = "HS256"
_TOKEN_MINUTES: int = int(os.environ.get("APP_TOKEN_MINUTES", "30"))

# ---------------------------------------------------------------------------
# Password hashing — using bcrypt directly (no passlib wrapper)
# ---------------------------------------------------------------------------


def hash_password(plain: str) -> str:
    return bcrypt.hashpw(plain.encode(), bcrypt.gensalt()).decode()


def verify_password(plain: str, hashed: str) -> bool:
    return bcrypt.checkpw(plain.encode(), hashed.encode())


# ---------------------------------------------------------------------------
# JWT helpers
# ---------------------------------------------------------------------------

def create_access_token(data: dict, expires_delta: timedelta | None = None) -> str:
    payload = data.copy()
    expire = datetime.now(timezone.utc) + (
        expires_delta or timedelta(minutes=_TOKEN_MINUTES)
    )
    payload["exp"] = expire
    return jwt.encode(payload, _SIGNING_KEY, algorithm=_ALGORITHM)


def decode_access_token(token: str) -> dict:
    return jwt.decode(token, _SIGNING_KEY, algorithms=[_ALGORITHM])


# ---------------------------------------------------------------------------
# FastAPI dependencies
# ---------------------------------------------------------------------------

_bearer = HTTPBearer()


def get_current_user(
    credentials: Annotated[HTTPAuthorizationCredentials, Depends(_bearer)],
    db: Annotated[sqlite3.Connection, Depends(get_db)],
) -> sqlite3.Row:
    """Validate JWT and return the authenticated user row."""
    exc = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Invalid or expired token",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = decode_access_token(credentials.credentials)
        user_id: int | None = payload.get("sub")
        if user_id is None:
            raise exc
    except jwt.PyJWTError:
        raise exc

    row = db.execute(
        "SELECT id, username, email, is_admin, created_at FROM users WHERE id = ?",
        (int(user_id),),
    ).fetchone()
    if row is None:
        raise exc
    return row


def require_admin(
    current_user: Annotated[sqlite3.Row, Depends(get_current_user)],
) -> sqlite3.Row:
    """Dependency that restricts a route to admin users only."""
    if not current_user["is_admin"]:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Admin access required",
        )
    return current_user


# ---------------------------------------------------------------------------
# Router
# ---------------------------------------------------------------------------

router = APIRouter(prefix="/auth", tags=["auth"])


@router.post("/register", status_code=status.HTTP_201_CREATED)
def register(body: UserRegister, db: Annotated[sqlite3.Connection, Depends(get_db)]):
    """Create a new user account."""
    existing = db.execute(
        "SELECT id FROM users WHERE username = ? OR email = ?",
        (body.username, body.email),
    ).fetchone()
    if existing:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Username or email already registered",
        )
    db.execute(
        "INSERT INTO users (username, email, hashed_password) VALUES (?, ?, ?)",
        (body.username, body.email, hash_password(body.password)),
    )
    db.commit()
    return {"message": "User created successfully"}


@router.post("/login", response_model=TokenResponse)
def login(body: UserLogin, db: Annotated[sqlite3.Connection, Depends(get_db)]):
    """Authenticate and return a JWT access token."""
    row = db.execute(
        "SELECT id, username, hashed_password, is_admin FROM users WHERE username = ?",
        (body.username,),
    ).fetchone()

    # VULN-003 (intentional): distinguishes "user not found" from "wrong password",
    # enabling username enumeration by an attacker.
    if row is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="User not found",
        )
    if not verify_password(body.password, row["hashed_password"]):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect password",
        )

    token = create_access_token(
        {"sub": str(row["id"]), "is_admin": bool(row["is_admin"])}
    )
    return TokenResponse(access_token=token)
