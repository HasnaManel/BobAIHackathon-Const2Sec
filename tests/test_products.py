"""Tests for products API endpoints."""

import pytest
from fastapi.testclient import TestClient


def _create_product(client, headers, name="Widget", price=9.99) -> dict:
    resp = client.post(
        "/products",
        json={"name": name, "description": "A test product", "price": price},
        headers=headers,
    )
    assert resp.status_code == 201, resp.text
    return resp.json()


class TestListProducts:
    def test_public_listing_requires_no_auth(self, client: TestClient):
        resp = client.get("/products")
        assert resp.status_code == 200
        assert isinstance(resp.json(), list)

    def test_returns_created_products(self, client: TestClient, auth_headers: dict):
        _create_product(client, auth_headers, name="ListTest")
        resp = client.get("/products")
        names = [p["name"] for p in resp.json()]
        assert "ListTest" in names


class TestGetProduct:
    def test_get_existing_product(self, client: TestClient, auth_headers: dict):
        product = _create_product(client, auth_headers, name="GetMe")
        resp = client.get(f"/products/{product['id']}")
        assert resp.status_code == 200
        assert resp.json()["name"] == "GetMe"

    def test_nonexistent_product_returns_404(self, client: TestClient):
        resp = client.get("/products/999999")
        assert resp.status_code == 404


class TestCreateProduct:
    def test_authenticated_user_can_create(
        self, client: TestClient, auth_headers: dict
    ):
        resp = client.post(
            "/products",
            json={"name": "NewProduct", "description": "desc", "price": 1.0},
            headers=auth_headers,
        )
        assert resp.status_code == 201
        data = resp.json()
        assert data["name"] == "NewProduct"
        assert "owner_id" in data

    def test_unauthenticated_creation_rejected(self, client: TestClient):
        resp = client.post(
            "/products",
            json={"name": "Anon", "description": "", "price": 1.0},
        )
        assert resp.status_code in (401, 403)

    def test_negative_price_rejected(self, client: TestClient, auth_headers: dict):
        resp = client.post(
            "/products",
            json={"name": "BadPrice", "description": "", "price": -5.0},
            headers=auth_headers,
        )
        assert resp.status_code == 422


class TestDeleteProduct:
    def test_owner_can_delete_own_product(
        self, client: TestClient, auth_headers: dict
    ):
        product = _create_product(client, auth_headers, name="DeleteMe")
        resp = client.delete(
            f"/products/{product['id']}", headers=auth_headers
        )
        assert resp.status_code == 204
    def test_non_owner_cannot_delete_product(
        self, client: TestClient, auth_headers: dict
    ):
        """FIND-009 / TEST-002: a non-owner, non-admin user must receive 403."""
        # Create a product as the regular user.
        product = _create_product(client, auth_headers, name="OwnedByRegular")
        # Register and log in a second, non-admin user.
        client.post(
            "/auth/register",
            json={"username": "thief", "email": "thief@example.com", "password": "ThiefPass1!"},
        )
        t = client.post(
            "/auth/login",
            json={"username": "thief", "password": "ThiefPass1!"},
        )
        thief_headers = {"Authorization": f"Bearer {t.json()['access_token']}"}
        resp = client.delete(f"/products/{product['id']}", headers=thief_headers)
        assert resp.status_code == 403

    def test_admin_can_delete_any_product(
        self, client: TestClient, auth_headers: dict, admin_headers: dict
    ):
        product = _create_product(client, auth_headers, name="AdminDelete")
        resp = client.delete(
            f"/products/{product['id']}", headers=admin_headers
        )
        assert resp.status_code == 204

    def test_delete_nonexistent_product_returns_404(
        self, client: TestClient, auth_headers: dict
    ):
        resp = client.delete("/products/999999", headers=auth_headers)
        assert resp.status_code == 404
