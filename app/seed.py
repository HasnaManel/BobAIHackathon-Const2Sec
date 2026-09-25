"""Admin seed script — run once to bootstrap a demo admin account.

Usage:
    python -m app.seed

Behaviour:
    - Creates the database tables if they do not already exist.
    - Generates a cryptographically random password.
    - Prints the password ONCE to stdout with a clear warning banner.
    - Hashes the password with bcrypt and upserts the admin user.
    - Subsequent runs update the password hash safely (safe to re-run).

IMPORTANT — DEMO ONLY:
    This script is intended for local demonstration purposes.
    The generated password is shown only once.  Save it immediately.
    Never hard-code credentials in source code.
"""

import secrets
import sqlite3

from app.database import DATABASE_PATH, init_db

_ADMIN_USERNAME = "admin"
_ADMIN_EMAIL = "admin@securegate.local"


def _hash_password(plain: str) -> str:
    import bcrypt  # local import keeps startup fast

    return bcrypt.hashpw(plain.encode(), bcrypt.gensalt()).decode()


def seed_admin(db_path: str = DATABASE_PATH) -> None:
    init_db(db_path)

    plain_password = secrets.token_urlsafe(16)
    hashed = _hash_password(plain_password)

    conn = sqlite3.connect(db_path)
    try:
        conn.execute(
            """
            INSERT INTO users (username, email, hashed_password, is_admin)
            VALUES (?, ?, ?, 1)
            ON CONFLICT(username) DO UPDATE SET
                hashed_password = excluded.hashed_password,
                email           = excluded.email,
                is_admin        = 1
            """,
            (_ADMIN_USERNAME, _ADMIN_EMAIL, hashed),
        )
        conn.commit()
    finally:
        conn.close()

    print()
    print("=" * 60)
    print("  SECUREGATE — DEMO ADMIN ACCOUNT SEEDED")
    print("  (DEMO USE ONLY — not for production)")
    print("=" * 60)
    print(f"  Username : {_ADMIN_USERNAME}")
    print(f"  Password : {plain_password}")
    print("=" * 60)
    print("  Save this password now — it will not be shown again.")
    print("=" * 60)
    print()


if __name__ == "__main__":
    seed_admin()
