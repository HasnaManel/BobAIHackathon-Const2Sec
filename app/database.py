"""Database layer — SQLite via Python's built-in sqlite3.

Exposes:
  init_db()   — create tables idempotently (called on startup).
  get_db()    — FastAPI dependency that yields an open Connection.

The database path is configured via the APP_DATABASE_PATH environment
variable (default: securegate.db).
"""

import os
import sqlite3
from pathlib import Path
from typing import Generator
import bcrypt

# FIND-005 fix: resolve the default path relative to the repository root so the
# correct database file is used regardless of the process's working directory.
_REPO_ROOT = Path(__file__).parent.parent
DATABASE_PATH: str = os.environ.get(
    "APP_DATABASE_PATH", str(_REPO_ROOT / "securegate.db")
)

# ---------------------------------------------------------------------------
# Schema
# ---------------------------------------------------------------------------

_SCHEMA = """
CREATE TABLE IF NOT EXISTS users (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    username        TEXT    NOT NULL UNIQUE,
    email           TEXT    NOT NULL UNIQUE,
    hashed_password TEXT    NOT NULL,
    is_admin        INTEGER NOT NULL DEFAULT 0,
    created_at      TEXT    NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS products (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    name        TEXT    NOT NULL,
    description TEXT    NOT NULL DEFAULT '',
    price       REAL    NOT NULL,
    owner_id    INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE
);
"""


def init_db(db_path: str = DATABASE_PATH) -> None:
    """Create all tables if they do not already exist."""
    conn = sqlite3.connect(db_path)
    try:
        conn.executescript(_SCHEMA)
        conn.commit()
    finally:
        conn.close()
        
def seed_demo_user(db_path: str = DATABASE_PATH) -> None:
    conn = sqlite3.connect(db_path)
    try:
        cur = conn.execute("SELECT COUNT(*) FROM users")
        count = cur.fetchone()[0]
        print(f"[seed] user count before seeding: {count}")
        if count == 0:
            hashed = bcrypt.hashpw(b"demo123", bcrypt.gensalt()).decode()
            conn.execute(
                "INSERT INTO users (username, email, hashed_password) VALUES (?, ?, ?)",
                ("demo", "demo@demo.com", hashed),
            )
            conn.commit()
            print("[seed] demo user created successfully")
        else:
            print("[seed] skipped — users already exist")
    except Exception as e:
        print(f"[seed] ERROR: {e}")
    finally:
        conn.close()
        
        


def get_db() -> Generator[sqlite3.Connection, None, None]:
    """FastAPI dependency — yields a database connection per request."""
    conn = sqlite3.connect(DATABASE_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    try:
        yield conn
    finally:
        conn.close()
