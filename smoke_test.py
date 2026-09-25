"""Manual API smoke test for SecureGate baseline verification."""
import httpx
import sys

BASE = "http://localhost:8765"
errors = []


def check(label, resp, expected_status):
    ok = resp.status_code == expected_status
    mark = "PASS" if ok else "FAIL"
    print(f"  [{mark}] {label}: HTTP {resp.status_code}")
    if not ok:
        errors.append(f"{label}: expected {expected_status}, got {resp.status_code}")


# Health check
r = httpx.get(f"{BASE}/health")
check("GET /health", r, 200)

# Register
r = httpx.post(
    f"{BASE}/auth/register",
    json={"username": "smokeuser", "email": "smoke@test.com", "password": "SmokePwd1!"},
)
check("POST /auth/register", r, 201)

# Duplicate register → 409
r2 = httpx.post(
    f"{BASE}/auth/register",
    json={"username": "smokeuser", "email": "smoke@test.com", "password": "SmokePwd1!"},
)
check("POST /auth/register duplicate -> 409", r2, 409)

# Login
r = httpx.post(
    f"{BASE}/auth/login",
    json={"username": "smokeuser", "password": "SmokePwd1!"},
)
check("POST /auth/login", r, 200)
token = r.json()["access_token"]
headers = {"Authorization": f"Bearer {token}"}

# Authenticated profile
r = httpx.get(f"{BASE}/users/me", headers=headers)
check("GET /users/me", r, 200)

# Unauthenticated profile → 403
r = httpx.get(f"{BASE}/users/me")
check("GET /users/me (no token) -> 403", r, 403)

# Create product
r = httpx.post(
    f"{BASE}/products",
    json={"name": "Smoke Widget", "description": "test", "price": 4.99},
    headers=headers,
)
check("POST /products", r, 201)
pid = r.json()["id"]

# List products (public)
r = httpx.get(f"{BASE}/products")
check("GET /products (public)", r, 200)

# Get single product (public)
r = httpx.get(f"{BASE}/products/{pid}")
check(f"GET /products/{pid}", r, 200)

# Second user
httpx.post(
    f"{BASE}/auth/register",
    json={"username": "othersmoke", "email": "other@smoke.com", "password": "OtherPwd1!"},
)
r2 = httpx.post(
    f"{BASE}/auth/login",
    json={"username": "othersmoke", "password": "OtherPwd1!"},
)
token2 = r2.json()["access_token"]
h2 = {"Authorization": f"Bearer {token2}"}

# Non-owner delete → 403
r = httpx.delete(f"{BASE}/products/{pid}", headers=h2)
check("DELETE /products non-owner -> 403", r, 403)

# Owner delete → 204
r = httpx.delete(f"{BASE}/products/{pid}", headers=headers)
check("DELETE /products owner -> 204", r, 204)

print()
if errors:
    print(f"FAILED: {len(errors)} check(s)")
    for e in errors:
        print(f"  - {e}")
    sys.exit(1)
else:
    print("All smoke checks PASSED")
