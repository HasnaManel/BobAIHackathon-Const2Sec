"""Authentication module — registration, login, JWT helpers, and dependencies.

Environment variables:
  APP_SIGNING_KEY       JWT signing secret (required; no insecure fallback).
  APP_TOKEN_MINUTES     Token lifetime in minutes (default: 30).
"""

import os
import sqlite3
import threading
import time
from collections import defaultdict
from datetime import datetime, timedelta, timezone
from typing import Annotated

import bcrypt
import jwt
from fastapi import APIRouter, Depends, HTTPException, Request, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

from app.database import get_db
from app.models import TokenResponse, UserLogin, UserProfile, UserRegister

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

# FIND-001 fix: require APP_SIGNING_KEY — raise RuntimeError at startup if absent.
_SIGNING_KEY_RAW: str = os.environ.get("APP_SIGNING_KEY", "").strip()
if not _SIGNING_KEY_RAW:
    raise RuntimeError(
        "APP_SIGNING_KEY environment variable is required but not set. "
        "Generate one with: python -c \"import secrets; print(secrets.token_hex(32))\""
    )
# FIND-001 fix: reject the well-known placeholder value from env.example so
# that a developer who copies the file verbatim cannot forge JWT tokens.
if _SIGNING_KEY_RAW.startswith("replace-me"):
    raise RuntimeError(
        "APP_SIGNING_KEY is still set to the example placeholder value. "
        "Generate a real key: python -c \"import secrets; print(secrets.token_hex(32))\""
    )
# FIND-004 fix: enforce minimum key entropy — reject keys shorter than 32 chars.
if len(_SIGNING_KEY_RAW) < 32:
    raise RuntimeError(
        "APP_SIGNING_KEY must be at least 32 characters. "
        "Generate one: python -c \"import secrets; print(secrets.token_hex(32))\""
    )
_SIGNING_KEY: str = _SIGNING_KEY_RAW
_ALGORITHM = "HS256"
_TOKEN_MINUTES: int = int(os.environ.get("APP_TOKEN_MINUTES", "30"))

# ---------------------------------------------------------------------------
# Rate limiter — FIND-006 fix
# ---------------------------------------------------------------------------
# Simple in-process sliding-window rate limiter keyed by IP address.
# Limit: 10 login/register attempts per minute per IP.

_RATE_LIMIT = 10          # max requests
_RATE_WINDOW = 60         # seconds
_rate_lock = threading.Lock()
_rate_buckets: dict[str, list[float]] = defaultdict(list)


def _check_rate_limit(request: Request) -> None:
    """Raise 429 if the caller has exceeded _RATE_LIMIT requests in _RATE_WINDOW seconds."""
    ip = request.client.host if request.client else "unknown"
    now = time.monotonic()
    cutoff = now - _RATE_WINDOW
    with _rate_lock:
        timestamps = _rate_buckets[ip]
        # Drop expired entries.
        _rate_buckets[ip] = [t for t in timestamps if t > cutoff]
        if len(_rate_buckets[ip]) >= _RATE_LIMIT:
            raise HTTPException(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                detail="Too many requests. Please try again later.",
            )
        _rate_buckets[ip].append(now)

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
        sub = payload.get("sub")
        if sub is None:
            raise exc
        # FIND-007 fix: guard against non-numeric sub claims to avoid ValueError → 500.
        try:
            user_id_int = int(sub)
        except (ValueError, TypeError):
            raise exc
    except jwt.PyJWTError:
        raise exc

    row = db.execute(
        "SELECT id, username, email, is_admin, created_at FROM users WHERE id = ?",
        (user_id_int,),
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
def register(request: Request, body: UserRegister, db: Annotated[sqlite3.Connection, Depends(get_db)]):
    """Create a new user account."""
    _check_rate_limit(request)
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
def login(request: Request, body: UserLogin, db: Annotated[sqlite3.Connection, Depends(get_db)]):
    """Authenticate and return a JWT access token."""
    _check_rate_limit(request)
    row = db.execute(
        "SELECT id, username, hashed_password, is_admin FROM users WHERE username = ?",
        (body.username,),
    ).fetchone()

    # FIND-004 fix: unified error message prevents username enumeration.
    if row is None or not verify_password(body.password, row["hashed_password"]):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid credentials",
            headers={"WWW-Authenticate": "Bearer"},
        )

    token = create_access_token(
        {"sub": str(row["id"]), "is_admin": bool(row["is_admin"])}
    )
    return TokenResponse(access_token=token)
