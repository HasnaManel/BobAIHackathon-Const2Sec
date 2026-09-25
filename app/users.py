"""User profile routes.

Endpoints:
  GET  /users/me            — return the authenticated user's own profile.
  GET  /users/{user_id}     — return any user's profile; full data for admins,
                              public data (id, username) for non-admins accessing
                              another user.
  PUT  /users/me            — update the authenticated user's email address.

NOTE — VULN-002 is introduced in Sub-Task 7:
  GET /users/{user_id} currently uses a parameterised query (correct).
  The vulnerability will replace it with unsafe string interpolation.
"""

import sqlite3
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, status

from app.auth import get_current_user
from app.database import get_db
from app.models import UserEmailUpdate, UserProfile

router = APIRouter(prefix="/users", tags=["users"])


@router.get("/me", response_model=UserProfile)
def get_my_profile(
    current_user: Annotated[sqlite3.Row, Depends(get_current_user)],
):
    """Return the authenticated user's full profile."""
    return UserProfile(
        id=current_user["id"],
        username=current_user["username"],
        email=current_user["email"],
        is_admin=bool(current_user["is_admin"]),
        created_at=current_user["created_at"],
    )


@router.get("/{user_id}")
def get_user_profile(
    user_id: int,
    current_user: Annotated[sqlite3.Row, Depends(get_current_user)],
    db: Annotated[sqlite3.Connection, Depends(get_db)],
):
    """Return a user profile.

    - Admins receive the full profile.
    - Regular users receive only public fields (id, username).
    """
    # VULN-002 (intentional): user_id is interpolated directly into the SQL
    # string instead of using a parameterised query — SQL injection risk.
    row = db.execute(
        f"SELECT id, username, email, is_admin, created_at FROM users WHERE id = {user_id}"
    ).fetchone()
    if row is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")

    if current_user["is_admin"]:
        return UserProfile(
            id=row["id"],
            username=row["username"],
            email=row["email"],
            is_admin=bool(row["is_admin"]),
            created_at=row["created_at"],
        )

    # Non-admin: only expose public fields.
    return {"id": row["id"], "username": row["username"]}


@router.put("/me", response_model=UserProfile)
def update_my_email(
    body: UserEmailUpdate,
    current_user: Annotated[sqlite3.Row, Depends(get_current_user)],
    db: Annotated[sqlite3.Connection, Depends(get_db)],
):
    """Update the authenticated user's email address."""
    existing = db.execute(
        "SELECT id FROM users WHERE email = ? AND id != ?",
        (body.email, current_user["id"]),
    ).fetchone()
    if existing:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Email already in use",
        )
    db.execute(
        "UPDATE users SET email = ? WHERE id = ?",
        (body.email, current_user["id"]),
    )
    db.commit()
    updated = db.execute(
        "SELECT id, username, email, is_admin, created_at FROM users WHERE id = ?",
        (current_user["id"],),
    ).fetchone()
    return UserProfile(
        id=updated["id"],
        username=updated["username"],
        email=updated["email"],
        is_admin=bool(updated["is_admin"]),
        created_at=updated["created_at"],
    )
