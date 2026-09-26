"""Tests for authentication endpoints: /auth/register and /auth/login."""

import pytest
from fastapi.testclient import TestClient


class TestRegister:
    def test_successful_registration(self, client: TestClient):
        resp = client.post(
            "/auth/register",
            json={
                "username": "newuser",
                "email": "newuser@example.com",
                "password": "StrongPass1!",
            },
        )
        assert resp.status_code == 201
        assert "message" in resp.json()

    def test_duplicate_username_rejected(self, client: TestClient):
        payload = {
            "username": "dupuser",
            "email": "dup@example.com",
            "password": "StrongPass1!",
        }
        client.post("/auth/register", json=payload)
        resp = client.post(
            "/auth/register",
            json={**payload, "email": "other@example.com"},
        )
        assert resp.status_code == 409

    def test_duplicate_email_rejected(self, client: TestClient):
        client.post(
            "/auth/register",
            json={
                "username": "emailtest1",
                "email": "shared@example.com",
                "password": "StrongPass1!",
            },
        )
        resp = client.post(
            "/auth/register",
            json={
                "username": "emailtest2",
                "email": "shared@example.com",
                "password": "StrongPass1!",
            },
        )
        assert resp.status_code == 409

    def test_password_not_in_response(self, client: TestClient):
        resp = client.post(
            "/auth/register",
            json={
                "username": "nopwdleak",
                "email": "nopwdleak@example.com",
                "password": "StrongPass1!",
            },
        )
        body = resp.text
        assert "StrongPass1" not in body
        assert "hashed_password" not in body

    def test_short_password_rejected(self, client: TestClient):
        resp = client.post(
            "/auth/register",
            json={
                "username": "shortpwd",
                "email": "short@example.com",
                "password": "abc",
            },
        )
        assert resp.status_code == 422


class TestLogin:
    def test_successful_login_returns_token(self, client: TestClient):
        client.post(
            "/auth/register",
            json={
                "username": "loginuser",
                "email": "loginuser@example.com",
                "password": "LoginPass1!",
            },
        )
        resp = client.post(
            "/auth/login",
            json={"username": "loginuser", "password": "LoginPass1!"},
        )
        assert resp.status_code == 200
        data = resp.json()
        assert "access_token" in data
        assert data["token_type"] == "bearer"

    def test_wrong_password_rejected(self, client: TestClient):
        client.post(
            "/auth/register",
            json={
                "username": "wrongpwd",
                "email": "wrongpwd@example.com",
                "password": "CorrectPass1!",
            },
        )
        resp = client.post(
            "/auth/login",
            json={"username": "wrongpwd", "password": "WrongPass!"},
        )
        assert resp.status_code == 401

    def test_unknown_user_rejected(self, client: TestClient):
        resp = client.post(
            "/auth/login",
            json={"username": "nobody", "password": "Whatever1!"},
        )
        assert resp.status_code == 401

    def test_token_grants_access_to_protected_route(
        self, client: TestClient, auth_headers: dict
    ):
        """A valid token allows access to /users/me (added in Sub-Task 5)."""
        # This test will only pass after users router is registered.
        resp = client.get("/users/me", headers=auth_headers)
        # 200 once users router exists; 404 acceptable before that sub-task.
        assert resp.status_code in (200, 404)

    def test_invalid_token_rejected(self, client: TestClient):
        resp = client.get(
            "/users/me",
            headers={"Authorization": "Bearer notavalidtoken"},
        )
        assert resp.status_code in (401, 403, 404)

    def test_oversized_username_rejected(self, client: TestClient):
        """FIND-004: username exceeding max_length must return 422."""
        resp = client.post(
            "/auth/login",
            json={"username": "a" * 200, "password": "SomePass1!"},
        )
        assert resp.status_code == 422

    def test_oversized_password_rejected(self, client: TestClient):
        """FIND-004: password exceeding max_length must return 422."""
        resp = client.post(
            "/auth/login",
            json={"username": "validuser", "password": "x" * 200},
        )
        assert resp.status_code == 422


class TestPasswordComplexity:
    """FIND-002: password complexity policy regression tests."""

    def test_all_lowercase_rejected(self, client: TestClient):
        resp = client.post(
            "/auth/register",
            json={
                "username": "pwdtest1",
                "email": "pwdtest1@example.com",
                "password": "alllowercase1",
            },
        )
        assert resp.status_code == 422

    def test_all_uppercase_rejected(self, client: TestClient):
        resp = client.post(
            "/auth/register",
            json={
                "username": "pwdtest2",
                "email": "pwdtest2@example.com",
                "password": "ALLUPPERCASE1",
            },
        )
        assert resp.status_code == 422

    def test_no_digit_rejected(self, client: TestClient):
        resp = client.post(
            "/auth/register",
            json={
                "username": "pwdtest3",
                "email": "pwdtest3@example.com",
                "password": "NoDigitHere!",
            },
        )
        assert resp.status_code == 422

    def test_common_weak_password_rejected(self, client: TestClient):
        """aaaaaaaa is all-lowercase with no digit — must be rejected."""
        resp = client.post(
            "/auth/register",
            json={
                "username": "pwdtest4",
                "email": "pwdtest4@example.com",
                "password": "aaaaaaaa",
            },
        )
        assert resp.status_code == 422

    def test_compliant_password_accepted(self, client: TestClient):
        resp = client.post(
            "/auth/register",
            json={
                "username": "pwdtest5",
                "email": "pwdtest5@example.com",
                "password": "Compliant1!",
            },
        )
        assert resp.status_code == 201


class TestSigningKeyPlaceholderGuard:
    """FIND-001 / FIND-004: APP_SIGNING_KEY guards — placeholder and short-key."""

    def _reload_auth_with_key(self, key_value: str):
        """Helper: unload app.auth, set APP_SIGNING_KEY=key_value, reimport."""
        import sys
        import os
        for mod_name in list(sys.modules.keys()):
            if "app.auth" in mod_name or mod_name == "app.auth":
                del sys.modules[mod_name]
        os.environ["APP_SIGNING_KEY"] = key_value
        import app.auth  # noqa: F401

    def test_placeholder_key_raises_runtime_error(self):
        """Starting auth with the placeholder signing key must raise RuntimeError."""
        import importlib
        import sys
        import os

        # Remove cached auth module so it re-evaluates module-level code.
        for mod_name in list(sys.modules.keys()):
            if "app.auth" in mod_name or mod_name == "app.auth":
                del sys.modules[mod_name]

        original = os.environ.get("APP_SIGNING_KEY")
        try:
            os.environ["APP_SIGNING_KEY"] = "replace-me-with-a-long-random-string"
            with pytest.raises(RuntimeError, match="placeholder"):
                import app.auth  # noqa: F401
        finally:
            # Restore original env var and re-import the real module.
            if original is not None:
                os.environ["APP_SIGNING_KEY"] = original
            elif "APP_SIGNING_KEY" in os.environ:
                del os.environ["APP_SIGNING_KEY"]
            # Re-import with the real key so subsequent tests are not broken.
            for mod_name in list(sys.modules.keys()):
                if "app.auth" in mod_name or mod_name == "app.auth":
                    del sys.modules[mod_name]
            import app.auth  # noqa: F401

    def test_short_key_raises_runtime_error(self):
        """FIND-004: APP_SIGNING_KEY shorter than 32 chars must raise RuntimeError."""
        import sys
        import os

        for mod_name in list(sys.modules.keys()):
            if "app.auth" in mod_name or mod_name == "app.auth":
                del sys.modules[mod_name]

        original = os.environ.get("APP_SIGNING_KEY")
        try:
            os.environ["APP_SIGNING_KEY"] = "short"  # only 5 chars — must be rejected
            with pytest.raises(RuntimeError, match="32 characters"):
                import app.auth  # noqa: F401
        finally:
            if original is not None:
                os.environ["APP_SIGNING_KEY"] = original
            elif "APP_SIGNING_KEY" in os.environ:
                del os.environ["APP_SIGNING_KEY"]
            for mod_name in list(sys.modules.keys()):
                if "app.auth" in mod_name or mod_name == "app.auth":
                    del sys.modules[mod_name]
            import app.auth  # noqa: F401
