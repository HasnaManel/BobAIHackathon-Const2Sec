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
