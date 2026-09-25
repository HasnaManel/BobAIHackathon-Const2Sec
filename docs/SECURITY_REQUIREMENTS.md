# SecureGate — Security Requirements

This document defines the security requirements for the SecureGate application.
It is used by the **Security Requirements Analyst** subagent to compare each
requirement against the actual implementation and report compliance status.

Every requirement is phrased as a MUST / MUST NOT obligation.
Each requirement has: an ID, a title, a description, acceptance criteria, and
a pointer to the relevant code area.

---

## AUTH — Authentication

### AUTH-001: Password Hashing

**Title:** All stored passwords MUST be hashed using a strong one-way algorithm.

**Description:**  
Plaintext passwords must never be stored in the database.  Passwords must be
hashed using a strong algorithm (e.g. bcrypt, argon2) with a per-password salt.

**Acceptance Criteria:**
- The `users.hashed_password` column contains a bcrypt (or equivalent) hash, never plaintext.
- The registration endpoint hashes the password before inserting into the database.
- The hashed value cannot be trivially reversed to recover the original password.

**Relevant code area:** `app/auth.py` → `hash_password()`, `app/auth.py` → `register()`

---

### AUTH-002: Passwords Must Not Be Returned in Responses

**Title:** API responses MUST NOT include hashed or plaintext passwords.

**Description:**  
No response body from any endpoint may include the `hashed_password` field or
any representation of the user's password.

**Acceptance Criteria:**
- `POST /auth/register` response does not include `hashed_password` or `password`.
- `GET /users/me` response does not include `hashed_password` or `password`.
- `GET /users/{user_id}` response does not include `hashed_password` or `password`.

**Relevant code area:** `app/models.py` → `UserProfile`, `app/auth.py` → `register()`

---

### AUTH-003: JWT Tokens Must Be Signed with a Strong Secret

**Title:** The application MUST refuse to start if no signing secret is configured.

**Description:**  
JWT tokens must be signed with a secret key read from the environment.  The
application MUST NOT fall back to any hardcoded or weak default value.  If
`APP_SIGNING_KEY` is absent or empty, startup MUST raise an error.

**Acceptance Criteria:**
- `APP_SIGNING_KEY` is required at startup; absence raises `RuntimeError` or `ValueError`.
- The codebase contains no hardcoded signing secret (including fallback strings like `"changeme"`).
- Tokens cannot be forged by an attacker who knows only the application source code.

**Relevant code area:** `app/auth.py` → `_SIGNING_KEY`

---

### AUTH-004: Generic Authentication Error Messages

**Title:** Login failures MUST return a single generic error message.

**Description:**  
The login endpoint MUST NOT distinguish between "user not found" and "wrong
password" in its response.  Distinct messages allow username enumeration.

**Acceptance Criteria:**
- Both "unknown username" and "wrong password" scenarios return the same HTTP status and message.
- The error detail does not mention whether the username exists.

**Relevant code area:** `app/auth.py` → `login()`

---

## AUTHZ — Authorization

### AUTHZ-001: Owners and Admins May Delete Resources; Others May Not

**Title:** DELETE operations on user-owned resources MUST enforce ownership or admin privilege.

**Description:**  
When a user attempts to delete a resource they do not own, the API MUST return
HTTP 403 Forbidden unless the user has admin privilege.

**Acceptance Criteria:**
- `DELETE /products/{id}` returns 403 when called by a non-owner, non-admin user.
- `DELETE /products/{id}` succeeds (204) when called by the product's owner.
- `DELETE /products/{id}` succeeds (204) when called by an admin regardless of ownership.

**Relevant code area:** `app/products.py` → `delete_product()`

---

### AUTHZ-002: Private Profile Data Must Not Leak to Unprivileged Users

**Title:** Full user profile data (including email) MUST only be visible to the owner or an admin.

**Description:**  
When a regular (non-admin) user retrieves another user's profile, the response
MUST only include public fields (e.g. id and username).  Fields such as email
and admin status MUST NOT be exposed.

**Acceptance Criteria:**
- `GET /users/{id}` by a non-admin user returns only `id` and `username` for other users.
- `GET /users/{id}` by an admin returns the full profile including `email` and `is_admin`.

**Relevant code area:** `app/users.py` → `get_user_profile()`

---

## INPUT — Input Validation

### INPUT-001: All Database Queries MUST Use Parameterised Statements

**Title:** SQL queries MUST use parameterised placeholders, not string interpolation.

**Description:**  
String formatting or f-strings MUST NOT be used to construct SQL queries that
include user-supplied values.  All variable values must be passed as parameters
to prevent SQL injection.

**Acceptance Criteria:**
- No SQL query in the codebase uses f-strings, `%` formatting, or `.format()` with user input.
- All queries use the `?` placeholder syntax and pass values as a separate tuple.

**Relevant code area:** `app/users.py` → `get_user_profile()`, `app/auth.py`, `app/products.py`

---

## ERROR — Error Handling

### ERROR-001: Error Responses Must Not Disclose Internal Details

**Title:** Error responses MUST NOT reveal internal implementation details, stack traces, or database schema.

**Description:**  
HTTP error responses must use generic, user-safe messages.  Internal details
such as table names, column names, exception tracebacks, or internal IDs must
not appear in any response body returned to the client.

**Acceptance Criteria:**
- 500-level errors do not include Python tracebacks in the response body.
- 401/403/404 error messages do not disclose whether a resource exists when access is denied.
- Login errors do not distinguish between missing user and wrong password (see AUTH-004).

**Relevant code area:** `app/auth.py`, `app/users.py`, `app/products.py`

---

## CONFIG — Secure Configuration

### CONFIG-001: Secrets Must Come From Environment Variables

**Title:** All secrets (signing keys, database credentials) MUST be supplied via environment variables with no insecure fallback.

**Description:**  
Source code MUST NOT contain hardcoded secrets or fallback values for security-
sensitive configuration.  If a required secret is absent at startup, the
application MUST fail to start with a clear error.

**Acceptance Criteria:**
- `APP_SIGNING_KEY` absence causes a `RuntimeError` at startup, not a silent fallback.
- No hardcoded secret values exist anywhere in the source code.
- `env.example` documents all required variables without containing real values.

**Relevant code area:** `app/auth.py` → `_SIGNING_KEY`, `app/database.py`

---

## TEST — Security Testing

### TEST-001: Authentication Boundary Tests

**Title:** Tests MUST verify that unauthenticated requests to protected endpoints are rejected.

**Description:**  
For every endpoint that requires authentication, there MUST be at least one
test that confirms the endpoint rejects requests without a valid Bearer token.

**Acceptance Criteria:**
- `GET /users/me`, `POST /products`, and `DELETE /products/{id}` each have a test for
  the unauthenticated/missing-token case returning 401 or 403.

**Relevant code area:** `tests/test_auth.py`, `tests/test_users.py`, `tests/test_products.py`

---

### TEST-002: Authorization Boundary Tests

**Title:** Tests MUST verify that users cannot access or mutate resources they do not own.

**Description:**  
There MUST be at least one test for each ownership-guarded endpoint that
confirms a different authenticated user (non-owner, non-admin) receives 403.

**Acceptance Criteria:**
- A test verifies that `DELETE /products/{id}` returns 403 when called by a
  non-owner, non-admin user.
- The test uses two distinct authenticated users.

**Relevant code area:** `tests/test_products.py` → `TestDeleteProduct`

---

### TEST-003: Input Validation Tests

**Title:** Tests MUST verify that invalid inputs are rejected with appropriate error codes.

**Description:**  
There MUST be tests for key validation rules: too-short passwords, negative
prices, and missing required fields.

**Acceptance Criteria:**
- A test verifies that a password shorter than 8 characters is rejected (422).
- A test verifies that a negative product price is rejected (422).

**Relevant code area:** `tests/test_auth.py`, `tests/test_products.py`

---

## Requirement Summary Table

| ID | Title | Area |
|----|-------|------|
| AUTH-001 | Passwords must be hashed | `app/auth.py` |
| AUTH-002 | Passwords must not be in responses | `app/models.py` |
| AUTH-003 | JWT signed with environment secret | `app/auth.py` |
| AUTH-004 | Generic login error messages | `app/auth.py` |
| AUTHZ-001 | Ownership enforced on DELETE | `app/products.py` |
| AUTHZ-002 | Private profile data not leaked | `app/users.py` |
| INPUT-001 | Parameterised SQL queries only | `app/users.py`, `app/auth.py` |
| ERROR-001 | No internal details in error responses | all routes |
| CONFIG-001 | Secrets from environment variables | `app/auth.py` |
| TEST-001 | Auth boundary tests exist | `tests/` |
| TEST-002 | Authz boundary tests exist | `tests/test_products.py` |
| TEST-003 | Input validation tests exist | `tests/` |
