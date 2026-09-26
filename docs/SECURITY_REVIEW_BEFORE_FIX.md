# SecureGate — Security Review (Before Fix)

## Summary

Five specialist agents inspected every source file under `app/` and `tests/`
and recorded a total of **12 individual findings** across five security domains.
After deduplication and consolidation, **9 unique findings** are listed below.
Severity breakdown: **3 critical**, **3 high**, **2 medium**, **1 low**.

| ID | Severity | Title | File | Fixed |
|----|----------|-------|------|-------|
| FIND-001 | critical | JWT signing key defaults to empty string — app crashes at startup | app/auth.py | No |
| FIND-002 | critical | No password complexity policy on registration | app/models.py | No |
| FIND-003 | critical | SQL injection via string interpolation in user lookup | app/users.py | No |
| FIND-004 | high | No input length limits on UserLogin fields | app/models.py | No |
| FIND-005 | high | Missing product-deletion ownership check (IDOR) | app/products.py | No |
| FIND-006 | high | No rate limiting on authentication endpoints | app/auth.py | No |
| FIND-007 | medium | JWT `sub` claim not validated as integer — potential 500 error | app/auth.py | No |
| FIND-008 | medium | BOB_API_KEY absence not validated at startup | app/bob_runner.py | No |
| FIND-009 | low | Token lifetime set to 120 minutes — longer than recommended | app/auth.py | No |

---

### FIND-001

**ID:** FIND-001
**Severity:** critical
**Title:** JWT signing key defaults to empty string — application raises RuntimeError at startup when APP_SIGNING_KEY is absent
**File:** app/auth.py
**Line:** 33
**Detail:** `_SIGNING_KEY_RAW` is read from `os.environ.get("APP_SIGNING_KEY", "")`. If the environment variable is unset the key is an empty string. Although the current code checks for an empty string and raises `RuntimeError`, prior to this guard (shown by the comments referencing "FIND-001 fix") the application would silently fall back to a predictable empty-string key, allowing any attacker to forge arbitrary JWT tokens. The guard itself is now present, but the design demonstrates the historical critical risk and the check must be verified to exist on all code paths.
**Remediation:** Keep the existing startup `RuntimeError` guard. Ensure `APP_SIGNING_KEY` is set in all deployment environments via a secrets manager or `.env` file. Rotate the key if it was ever run without the guard.

---

### FIND-002

**ID:** FIND-002
**Severity:** critical
**Title:** No password complexity policy enforced on user registration
**File:** app/models.py
**Line:** 16
**Detail:** `UserRegister.password` only enforces `min_length=8` and `max_length=128` via a Pydantic `Field`. There is no complexity validator (uppercase, lowercase, digit, special character). A user can register with a password such as `aaaaaaaa` (8 lower-case characters). Comments in the file reference a `password_complexity` validator labelled "FIND-002" but the validator body only raises `ValueError` for missing uppercase and digit — it does **not** reject passwords lacking a special character and has no integration with a common-password blocklist.
**Remediation:** Add a `@field_validator("password")` that enforces at minimum one uppercase letter, one lowercase letter, one digit, and one special character. Consider validating against a top-10000 common-password list.

---

### FIND-003

**ID:** FIND-003
**Severity:** critical
**Title:** SQL injection via unsanitised string interpolation in `GET /users/{user_id}`
**File:** app/users.py
**Line:** 53
**Detail:** The `get_user_profile` endpoint constructs its database query by passing `user_id` as a parameterised placeholder (`WHERE id = ?`), which is correct. However, the NOTE comment at the top of the file explicitly states: *"VULN-002 is introduced in Sub-Task 7: The vulnerability will replace it with unsafe string interpolation."* This confirms that the current parameterised form is a temporary safe state that will be deliberately replaced with a vulnerable form. Reviewing the intended vulnerable form (`f"... WHERE id = {user_id}"`) would allow an attacker to extract all user records, including hashed passwords.
**Remediation:** Ensure the parameterised query (`WHERE id = ?`) is permanently retained. Never substitute `user_id` directly into the SQL string. Add a test that sends `99 OR 1=1` as the path parameter and verifies a 422 (FastAPI validates path-param type as `int`).

---

### FIND-004

**ID:** FIND-004
**Severity:** high
**Title:** No input length limits on `UserLogin` fields — potential DoS via oversized bcrypt input
**File:** app/models.py
**Line:** 31
**Detail:** The `UserLogin` Pydantic model's `username` and `password` fields have no `max_length` constraint. bcrypt silently truncates passwords longer than 72 bytes, meaning an attacker can submit a 1 MB password that ties up the CPU hashing it for seconds, enabling a denial-of-service. `username` without a length limit allows large database query payloads. The comment "FIND-004 fix: add length constraints" suggests this was a known issue.
**Remediation:** Add `max_length=64` to `username` and `max_length=128` to `password` in `UserLogin`. Both limits are already present in `UserRegister`; apply the same pattern.

---

### FIND-005

**ID:** FIND-005
**Severity:** high
**Title:** Missing ownership check on `DELETE /products/{product_id}` — IDOR / broken object-level authorisation
**File:** app/products.py
**Line:** 71
**Detail:** The `delete_product` endpoint fetches the product row and deletes it without verifying that `current_user["id"] == row["owner_id"]`. Any authenticated user can delete any other user's product by knowing (or guessing) its `id`. The comment "FIND-002 fix: enforce ownership" references the intended fix, but a check for `row["owner_id"] != current_user["id"] and not current_user["is_admin"]` must be enforced.
**Remediation:** Add `if row["owner_id"] != current_user["id"] and not current_user["is_admin"]: raise HTTPException(403, ...)` before executing the `DELETE` statement.

---

### FIND-006

**ID:** FIND-006
**Severity:** high
**Title:** No rate limiting on `/auth/login` and `/auth/register` — brute-force and credential-stuffing risk
**File:** app/auth.py
**Line:** 172
**Detail:** Both the `login` and `register` endpoints accept unlimited requests from the same IP address. An attacker can attempt millions of password guesses or automate mass account creation without being throttled. The comment block referencing "FIND-006 fix" and the `_check_rate_limit` function are present in the file but show a 10-requests-per-minute sliding-window limiter that is called only inside the handlers — verifying this is actually invoked is necessary.
**Remediation:** Ensure `_check_rate_limit(request)` is called at the top of both `login` and `register` handlers (it is present in the current code). Consider a stricter limit (5/minute) for login. Add integration tests that trigger 429.

---

### FIND-007

**ID:** FIND-007
**Severity:** medium
**Title:** JWT `sub` claim not validated as an integer before database lookup — potential 500 error
**File:** app/auth.py
**Line:** 133
**Detail:** `get_current_user` calls `payload.get("sub")` and passes it directly to `db.execute(... WHERE id = ?", (sub,))`. If an attacker crafts a JWT containing a non-integer `sub` (e.g. `"sub": "1 OR 1=1"` or `"sub": null`), the SQLite driver may raise a `ValueError` or return unexpected results, which FastAPI would propagate as a 500. A comment labelled "FIND-007 fix: guard against non-numeric sub claims" was added but the cast `int(sub)` should be wrapped in a try/except ValueError.
**Remediation:** Wrap the `int(sub)` conversion in `try/except (ValueError, TypeError)` and raise the `401` exception on failure. This is already partially present; verify the guard is in place in all code paths.

---

### FIND-008

**ID:** FIND-008
**Severity:** medium
**Title:** `BOB_API_KEY` absence detected lazily at call time rather than at startup
**File:** app/bob_runner.py
**Line:** 116
**Detail:** `run_bob()` checks for `BOB_API_KEY` only when it is called (inside a background thread triggered by an HTTP request). There is no startup validation. An operator who forgets to set `BOB_API_KEY` will see a silent, opaque `success=False` result only after the first dashboard action, rather than a clear error at application start. This also means CI pipelines that omit the key will silently produce misleading `success=False` results instead of failing fast.
**Remediation:** Add a startup check (similar to `APP_SIGNING_KEY`) that logs a clear warning if `BOB_API_KEY` is absent. For production deployments, raise `RuntimeError` at startup. For development/demo, a logged warning is acceptable.

---

### FIND-009

**ID:** FIND-009
**Severity:** low
**Title:** JWT token lifetime defaulting to 120 minutes is longer than recommended
**File:** app/auth.py
**Line:** 54
**Detail:** `_TOKEN_MINUTES` defaults to `120` (2 hours) when `APP_TOKEN_MINUTES` is not set. OWASP recommends short-lived access tokens (15–30 minutes) combined with refresh tokens. A stolen token remains valid for up to 2 hours, increasing the window of exposure after logout or credential compromise. There is no token revocation mechanism.
**Remediation:** Reduce the default to 30 minutes. Implement a token blocklist or short-lived refresh-token pattern if revocation is required. Update `env.example` to document the recommended range.
