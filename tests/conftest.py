"""pytest configuration and shared fixtures for SecureGate tests.

All tests use an in-memory SQLite database so they are completely isolated
from any real database file on disk.

Available fixtures:
  client          — TestClient with an in-memory DB (all tables created).
  auth_headers    — Bearer token headers for a pre-created regular user.
  admin_headers   — Bearer token headers for a pre-created admin user.
"""

import sqlite3

import pytest
from fastapi.testclient import TestClient

from app.database import get_db, init_db
from app.main import app

# ---------------------------------------------------------------------------
# In-memory database shared across all tests in a session.
# Using check_same_thread=False because TestClient may use threads.
# ---------------------------------------------------------------------------

_IN_MEMORY_CONN: sqlite3.Connection | None = None


def _get_test_db():
    """Dependency override — always returns the in-memory connection."""
    global _IN_MEMORY_CONN
    assert _IN_MEMORY_CONN is not None, "Test DB not initialised"
    _IN_MEMORY_CONN.row_factory = sqlite3.Row
    _IN_MEMORY_CONN.execute("PRAGMA foreign_keys = ON")
    yield _IN_MEMORY_CONN


@pytest.fixture(scope="session")
def client():
    """TestClient backed by a fresh in-memory database."""
    global _IN_MEMORY_CONN
    _IN_MEMORY_CONN = sqlite3.connect(":memory:", check_same_thread=False)
    init_db(":memory:")  # runs schema on same connection indirectly

    # Manually apply schema directly to our shared connection.
    from app.database import _SCHEMA
    _IN_MEMORY_CONN.executescript(_SCHEMA)
    _IN_MEMORY_CONN.commit()

    app.dependency_overrides[get_db] = _get_test_db

    with TestClient(app, raise_server_exceptions=True) as c:
        yield c

    app.dependency_overrides.clear()
    _IN_MEMORY_CONN.close()
    _IN_MEMORY_CONN = None


# ---------------------------------------------------------------------------
# Helper: register + login a user, return auth headers.
# ---------------------------------------------------------------------------

def _create_user_and_login(client, username: str, password: str, email: str) -> dict:
    client.post(
        "/auth/register",
        json={"username": username, "email": email, "password": password},
    )
    resp = client.post(
        "/auth/login",
        json={"username": username, "password": password},
    )
    token = resp.json()["access_token"]
    return {"Authorization": f"Bearer {token}"}


@pytest.fixture(scope="session")
def auth_headers(client):
    """Auth headers for a regular (non-admin) test user."""
    return _create_user_and_login(
        client,
        username="testuser",
        password="TestPass123!",
        email="testuser@example.com",
    )


@pytest.fixture(scope="session")
def admin_headers(client):
    """Auth headers for an admin test user.

    The user is created as a regular user via the API, then elevated to admin
    directly in the test database — mimicking the seed script behaviour.
    """
    headers = _create_user_and_login(
        client,
        username="testadmin",
        password="AdminPass123!",
        email="testadmin@example.com",
    )
    # Elevate to admin in the in-memory DB.
    global _IN_MEMORY_CONN
    _IN_MEMORY_CONN.execute(
        "UPDATE users SET is_admin = 1 WHERE username = 'testadmin'"
    )
    _IN_MEMORY_CONN.commit()
    # Re-login so the JWT carries is_admin=True.
    return _create_user_and_login(
        client,
        username="testadmin",
        password="AdminPass123!",
        email="testadmin@example.com",
    )
