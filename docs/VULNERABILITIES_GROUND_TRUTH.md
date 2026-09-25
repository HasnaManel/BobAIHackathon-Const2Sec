# SecureGate — Vulnerability Ground Truth

> **EVALUATION USE ONLY — DO NOT SHARE WITH REVIEW AGENTS**
>
> This document is the authoritative record of intentionally introduced
> weaknesses for the SecureReview Copilot hackathon evaluation.
> Review agents must NOT be given access to this file.
> It is used only to calculate detection accuracy after the workflow runs.

---

## Summary

| ID | Category | Severity | File | Status |
|----|----------|----------|------|--------|
| VULN-001 | Missing Authorization | High | `app/products.py` | Introduced |
| VULN-002 | SQL Injection | High | `app/users.py` | Introduced |
| VULN-003 | Information Disclosure | Medium | `app/auth.py` | Introduced |
| VULN-004 | Insecure Default Configuration | High | `app/auth.py` | Introduced |
| VULN-005 | Missing Security Regression Test | Medium | `tests/test_products.py` | Introduced |

---

## VULN-001 — Missing Authorization on Product Deletion

**Category:** Missing Authorization  
**Severity:** High  
**File:** `app/products.py`  
**Function:** `delete_product` (`DELETE /products/{product_id}`)

**Description:**  
The ownership and admin check was removed from the DELETE endpoint.
Any authenticated user can delete any product regardless of ownership.

**Vulnerable code:**
```python
# Ownership check is absent — any authenticated user can delete any product
db.execute("DELETE FROM products WHERE id = ?", (product_id,))
db.commit()
```

**Expected fix:**  
Restore the ownership/admin guard before executing the DELETE:
```python
if row["owner_id"] != current_user["id"] and not current_user["is_admin"]:
    raise HTTPException(status_code=403, detail="Not authorised to delete this product")
```

**Expected regression test:**  
A test asserting that `DELETE /products/{id}` returns 403 when called by a
non-owner non-admin user.

---

## VULN-002 — SQL Injection in User Lookup

**Category:** SQL Injection  
**Severity:** High  
**File:** `app/users.py`  
**Function:** `get_user_profile` (`GET /users/{user_id}`)

**Description:**  
The `user_id` path parameter is interpolated directly into an f-string SQL
query. An attacker who can inject into this value could read, modify, or
delete arbitrary data.

**Vulnerable code:**
```python
row = db.execute(
    f"SELECT id, username, email, is_admin, created_at FROM users WHERE id = {user_id}"
).fetchone()
```

**Expected fix:**  
Use a parameterised query:
```python
row = db.execute(
    "SELECT id, username, email, is_admin, created_at FROM users WHERE id = ?",
    (user_id,),
).fetchone()
```

**Note:** FastAPI validates `user_id` as `int`, which partially mitigates this
in practice, but the pattern is wrong and any future type loosening would
reintroduce the full injection risk.

---

## VULN-003 — Username Enumeration via Distinct Error Messages

**Category:** Information Disclosure  
**Severity:** Medium  
**File:** `app/auth.py`  
**Function:** `login` (`POST /auth/login`)

**Description:**  
The login endpoint returns different error messages depending on whether the
username exists: `"User not found"` vs `"Incorrect password"`. An attacker can
use this to enumerate valid usernames by observing the response.

**Vulnerable code:**
```python
if row is None:
    raise HTTPException(status_code=401, detail="User not found")
if not verify_password(body.password, row["hashed_password"]):
    raise HTTPException(status_code=401, detail="Incorrect password")
```

**Expected fix:**  
Return a single generic error message for both cases:
```python
raise HTTPException(status_code=401, detail="Invalid username or password")
```

---

## VULN-004 — Insecure Default Secret Key

**Category:** Insecure Default Configuration  
**Severity:** High  
**File:** `app/auth.py`  
**Variable:** `_SIGNING_KEY`

**Description:**  
When the `APP_SIGNING_KEY` environment variable is not set, the application
silently falls back to the weak hardcoded string `"changeme"` for JWT signing.
An attacker who knows this default can forge valid JWT tokens for any user,
including admins.

**Vulnerable code:**
```python
_SIGNING_KEY: str = os.environ.get("APP_SIGNING_KEY", "changeme")
```

**Expected fix:**  
Raise a `RuntimeError` (or `ValueError`) at startup when the environment
variable is absent, preventing the application from starting in an insecure
state:
```python
_SIGNING_KEY: str = os.environ.get("APP_SIGNING_KEY") or ""
if not _SIGNING_KEY:
    raise RuntimeError("APP_SIGNING_KEY environment variable is not set")
```

---

## VULN-005 — Missing Regression Test for Non-Owner Deletion

**Category:** Missing Security Regression Test  
**Severity:** Medium  
**File:** `tests/test_products.py`  
**Class:** `TestDeleteProduct`

**Description:**  
There is no test asserting that a non-owner, non-admin user receives a 403
when attempting to delete another user's product. This means VULN-001 goes
undetected by the test suite — the vulnerability was introduced and all tests
still pass.

**Evidence:**  
The comment in `test_products.py` explicitly marks the gap:
```python
# VULN-005 (intentional gap): the test that would assert a non-owner cannot
# delete another user's product is ABSENT here.
```

**Expected fix:**  
Add a test:
```python
def test_nonowner_cannot_delete(self, client, auth_headers):
    product = _create_product(client, auth_headers, name="Protected")
    # second user registers and logs in ...
    resp = client.delete(f"/products/{product['id']}", headers=other_headers)
    assert resp.status_code == 403
```

---

## Detection Scoring

The SecureReview Copilot workflow is scored as follows:

| Finding | Detected? | Correctly Remediated? | Regression Test Added? |
|---------|-----------|----------------------|----------------------|
| VULN-001 | — | — | — |
| VULN-002 | — | — | — |
| VULN-003 | — | — | — |
| VULN-004 | — | — | — |
| VULN-005 | — | — | — |

Fill in this table after the workflow runs to calculate detection accuracy.
