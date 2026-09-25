"""Tests for user profile endpoints."""

import pytest
from fastapi.testclient import TestClient


class TestGetMyProfile:
    def test_authenticated_user_gets_own_profile(
        self, client: TestClient, auth_headers: dict
    ):
        resp = client.get("/users/me", headers=auth_headers)
        assert resp.status_code == 200
        data = resp.json()
        assert "id" in data
        assert "username" in data
        assert "email" in data
        assert "hashed_password" not in data

    def test_unauthenticated_request_rejected(self, client: TestClient):
        resp = client.get("/users/me")
        assert resp.status_code in (401, 403)

    def test_invalid_token_rejected(self, client: TestClient):
        resp = client.get(
            "/users/me",
            headers={"Authorization": "Bearer bad.token.here"},
        )
        assert resp.status_code in (401, 403)


class TestGetUserById:
    def test_admin_sees_full_profile(
        self, client: TestClient, admin_headers: dict, auth_headers: dict
    ):
        # Get own profile first to learn the id.
        me = client.get("/users/me", headers=auth_headers).json()
        resp = client.get(f"/users/{me['id']}", headers=admin_headers)
        assert resp.status_code == 200
        data = resp.json()
        assert "email" in data
        assert "is_admin" in data

    def test_regular_user_sees_only_public_fields(
        self, client: TestClient, auth_headers: dict, admin_headers: dict
    ):
        # Get admin's id.
        me = client.get("/users/me", headers=admin_headers).json()
        resp = client.get(f"/users/{me['id']}", headers=auth_headers)
        assert resp.status_code == 200
        data = resp.json()
        assert "id" in data
        assert "username" in data
        # email must not leak to non-admin viewing another user.
        assert "email" not in data

    def test_nonexistent_user_returns_404(
        self, client: TestClient, auth_headers: dict
    ):
        resp = client.get("/users/99999", headers=auth_headers)
        assert resp.status_code == 404


class TestUpdateMyEmail:
    def test_authenticated_user_can_update_email(
        self, client: TestClient
    ):
        # Register a dedicated user for this test.
        client.post(
            "/auth/register",
            json={
                "username": "emailupdate",
                "email": "before@example.com",
                "password": "UpdatePass1!",
            },
        )
        token_resp = client.post(
            "/auth/login",
            json={"username": "emailupdate", "password": "UpdatePass1!"},
        )
        headers = {"Authorization": f"Bearer {token_resp.json()['access_token']}"}

        resp = client.put(
            "/users/me",
            json={"email": "after@example.com"},
            headers=headers,
        )
        assert resp.status_code == 200
        assert resp.json()["email"] == "after@example.com"

    def test_duplicate_email_rejected(self, client: TestClient, auth_headers: dict):
        # Use testuser's email from fixture — try to claim it from another account.
        me = client.get("/users/me", headers=auth_headers).json()
        original_email = me["email"]

        # Register another user.
        client.post(
            "/auth/register",
            json={
                "username": "dup_email_tester",
                "email": "unique_dup@example.com",
                "password": "DupPass1!",
            },
        )
        t = client.post(
            "/auth/login",
            json={"username": "dup_email_tester", "password": "DupPass1!"},
        )
        h2 = {"Authorization": f"Bearer {t.json()['access_token']}"}

        resp = client.put(
            "/users/me",
            json={"email": original_email},
            headers=h2,
        )
        assert resp.status_code == 409
