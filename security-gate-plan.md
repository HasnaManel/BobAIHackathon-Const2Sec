# Security Gate — Implementation Plan

## Top-Level Overview

Build a minimal but realistic Python + FastAPI + pytest demo application called **SecureGate**
inside the existing hackathon repository. The application is purpose-built to serve as a target
for the **SecureReview Copilot** Bob workflow. It must be:

- Small enough to be understood at a glance by hackathon judges.
- Realistic enough to contain meaningful security-sensitive paths (auth, authz, DB access, API).
- Intentionally weakened with a small, documented set of security/testing gaps that the Bob
  workflow can later detect and fix.
- Runnable locally with a single command and a standard `pytest` invocation.

The application is **NOT the main product** — it is the realistic sample that Bob analyses.

## Confirmed Design Decisions (approved by user)

| Decision | Choice |
|----------|--------|
| Application name | **SecureGate** |
| Weaknesses | All five (VULN-001 through VULN-005) — unchanged |
| Admin seeding | Seed script generates a local credential; password printed once to stdout and stored hashed in DB — never in source code |
| Verification gate | Both `pytest` full suite AND manual API smoke checks via `httpx`/curl |

---

## Recommended Repository Structure

```
BobAIHackathon-Const2Sec/
├── app/
│   ├── __init__.py
│   ├── main.py              # FastAPI app factory + startup
│   ├── database.py          # SQLite connection / schema setup
│   ├── models.py            # Pydantic request/response models
│   ├── auth.py              # Registration, login, JWT helpers
│   ├── users.py             # User profile routes (protected)
│   └── products.py          # Product API routes (partially protected)
├── docs/
│   ├── SECURITY_REQUIREMENTS.md   # Formal security requirements with IDs
│   └── VULNERABILITIES_GROUND_TRUTH.md  # (Phase 2 – not yet)
├── tests/
│   ├── conftest.py          # pytest fixtures (test client, seeded DB)
│   ├── test_auth.py         # Auth happy-path and edge-case tests
│   ├── test_users.py        # User profile access tests
│   └── test_products.py     # Product API tests
├── requirements.txt         # fastapi, uvicorn, pyjwt, passlib, pytest, httpx
├── .env.example             # Documented env vars (no real secrets)
└── README.md                (update with run instructions)
```

---

## Phase Overview

| Phase | Name | Depends on |
|-------|------|-----------|
| 1 | Baseline SecureGate application | — |
| 2 | Security requirements document | Phase 1 |
| 3 | Controlled vulnerable version | Phase 2 |
| 4 | SecureReview Copilot workflow | Phase 3 |
| 5 | Parallel subagents | Phase 4 |
| 6 | Finding consolidation | Phase 5 |
| 7 | Remediation and testing | Phase 6 |
| 8 | Independent verification | Phase 7 |
| 9 | Final reporting | Phase 8 |
| 10 | Measurement and hackathon demo | Phase 9 |

---

## Sub-Tasks

---

### Sub-Task 1 — Project scaffold and dependencies

**Status:** [ ] pending

**Intent**
Create the skeleton files and `requirements.txt` so the project is importable and runnable before
any feature code is added.

**Expected Outcomes**
- `requirements.txt` lists all runtime and test dependencies.
- All `__init__.py` files and stub module files exist (no import errors).
- `app/main.py` exports a minimal FastAPI app that returns 200 on `GET /health`.
- `.env.example` documents the required environment variables.

**Todo List**
1. Write `requirements.txt` with: `fastapi`, `uvicorn[standard]`, `pyjwt`, `passlib[bcrypt]`,
   `python-multipart`, `pytest`, `httpx`, `pytest-cov`.
2. Create `app/__init__.py` (empty).
3. Create `app/main.py` with a FastAPI app, `/health` endpoint, and lifespan startup hook.
4. Create `.env.example` documenting `SECRET_KEY`, `DATABASE_URL`, `ACCESS_TOKEN_EXPIRE_MINUTES`.
5. Verify `python -m pytest --collect-only` runs without import errors.

**Relevant Context**
- `app/` directory already exists but is empty.
- `requirements.txt` already exists but is empty.

---

### Sub-Task 2 — Database layer

**Status:** [ ] pending

**Intent**
Implement an SQLite database module that creates the schema on startup and exposes a connection
helper used by all route handlers.

**Expected Outcomes**
- `app/database.py` can create the `users` and `products` tables idempotently.
- A `get_db()` dependency function is available for FastAPI dependency injection.
- Tables: `users(id, username, email, hashed_password, is_admin, created_at)`,
  `products(id, name, description, price, owner_id)`.

**Todo List**
1. Write `app/database.py` with `init_db()` and `get_db()` using Python's built-in `sqlite3`.
2. Call `init_db()` from the FastAPI lifespan startup hook in `app/main.py`.
3. Write `app/seed.py` — a standalone script (`python -m app.seed`) that:
   - Generates a random 16-character password using `secrets.token_urlsafe`.
   - Prints it once to stdout with a clear "DEMO ONLY — save this password" banner.
   - Hashes it with bcrypt and inserts/upserts an `admin` user into the database.
   - Is safe to re-run (upsert, not duplicate insert).
4. Write `tests/conftest.py` with a `test_client` fixture that uses an in-memory SQLite DB
   so tests do not touch the real database.

**Relevant Context**
- Use Python's built-in `sqlite3` (no ORM) to keep dependencies minimal.
- The `conftest.py` fixture must override `get_db` via FastAPI dependency override so tests are
  isolated.
- `app/seed.py` must never hardcode a password — it always generates a fresh one at runtime.
- The seed script is documented in `.env.example` and `README.md`.

---

### Sub-Task 3 — Pydantic models

**Status:** [ ] pending

**Intent**
Define all request/response Pydantic models in one place to keep route handlers clean and to
make the API contract explicit.

**Expected Outcomes**
- `app/models.py` contains: `UserRegister`, `UserLogin`, `UserProfile`, `TokenResponse`,
  `ProductCreate`, `ProductResponse`.
- Passwords are `str`, not returned in any response model.

**Todo List**
1. Write `app/models.py` with all Pydantic v2 models.
2. Ensure `UserProfile` and `ProductResponse` do not include `hashed_password`.

**Relevant Context**
- FastAPI uses Pydantic v2 by default.

---

### Sub-Task 4 — Authentication module

**Status:** [ ] pending

**Intent**
Implement user registration, login, and JWT token creation/validation. This module is the
highest-value target for the security analysis phase, so it must be realistic.

**Expected Outcomes**
- `POST /auth/register` creates a new user with a bcrypt-hashed password.
- `POST /auth/login` returns a signed JWT on success, 401 on failure.
- A `get_current_user` dependency validates the Bearer token on protected routes.
- An `require_admin` dependency enforces admin-only routes.

**Todo List**
1. Write `app/auth.py`:
   - `hash_password(plain)` using `passlib`.
   - `verify_password(plain, hashed)` using `passlib`.
   - `create_access_token(data, expires_delta)` using `pyjwt`.
   - `get_current_user(token, db)` FastAPI dependency.
   - `require_admin(current_user)` FastAPI dependency.
   - `router` with `POST /auth/register` and `POST /auth/login`.
2. Include the auth router in `app/main.py`.
3. Write `tests/test_auth.py` covering:
   - Successful registration.
   - Duplicate username rejection.
   - Successful login.
   - Invalid credentials rejection.
   - Token validation on a protected endpoint.

**Relevant Context**
- `SECRET_KEY` must be read from an environment variable (not hardcoded).
- Passwords must never appear in any response body.

---

### Sub-Task 5 — User profile routes

**Status:** [ ] pending

**Intent**
Implement user profile read/update routes that require authentication and enforce ownership,
making them a meaningful target for authorization analysis.

**Expected Outcomes**
- `GET /users/me` returns the authenticated user's profile.
- `GET /users/{user_id}` returns any user's public profile (admin sees full profile).
- `PUT /users/me` allows a user to update their own email.
- Accessing another user's private data without admin rights returns 403.

**Todo List**
1. Write `app/users.py` with the three routes above.
2. Use `get_current_user` dependency on all routes.
3. Include the users router in `app/main.py`.
4. Write `tests/test_users.py` covering:
   - Authenticated profile fetch.
   - Unauthenticated request rejection.
   - Ownership enforcement.

**Relevant Context**
- Admin flag is set in the `users` table; the JWT payload carries `is_admin`.

---

### Sub-Task 6 — Products API

**Status:** [ ] pending

**Intent**
Implement a small product catalogue API that has both public and protected endpoints.
Product creation is restricted to authenticated users; reading is public.
This creates an authorization boundary for the security analysis to examine.

**Expected Outcomes**
- `GET /products` returns all products (public, no auth required).
- `GET /products/{product_id}` returns a single product (public).
- `POST /products` creates a product owned by the authenticated user.
- `DELETE /products/{product_id}` deletes a product; only the owner or an admin can delete.

**Todo List**
1. Write `app/products.py` with the four routes above.
2. Include the products router in `app/main.py`.
3. Write `tests/test_products.py` covering:
   - Public product listing.
   - Authenticated product creation.
   - Unauthenticated creation rejection.
   - Deletion by owner succeeds.
   - Deletion by non-owner returns 403.

**Relevant Context**
- `owner_id` in the `products` table links to `users.id`.

---

### Sub-Task 7 — Intentional security and testing weaknesses

**Status:** [ ] pending

**Intent**
Introduce a small, documented set of realistic weaknesses that the SecureReview Copilot will
later detect. The weaknesses must be safe and local — they cannot affect systems outside the
project.

**Planned Weaknesses (4–5 issues)**

| ID | Category | Location | Description |
|----|----------|----------|-------------|
| VULN-001 | Missing authorization | `products.py` `DELETE /products/{id}` | The ownership check is present in the spec but the actual implementation will skip it, allowing any authenticated user to delete any product. |
| VULN-002 | SQL injection risk | `users.py` `GET /users/{user_id}` | The `user_id` path parameter will be interpolated directly into a raw SQL query string instead of using parameterised queries. |
| VULN-003 | Information disclosure | `auth.py` error handling | Login failure returns a detailed error distinguishing "user not found" from "wrong password", leaking username enumeration. |
| VULN-004 | Insecure default configuration | `auth.py` / `main.py` | `SECRET_KEY` falls back to a hardcoded weak default (`"changeme"`) when the environment variable is missing, instead of raising at startup. |
| VULN-005 | Missing security regression tests | `tests/` | No test verifies that a non-owner cannot delete another user's product (VULN-001 has no test guard). |

**Expected Outcomes**
- The weaknesses are present in the committed code.
- The application still passes its existing tests (the tests do not cover the weak paths).
- A `docs/VULNERABILITIES_GROUND_TRUTH.md` file records each weakness for later evaluation
  accuracy measurement. The review agents must NOT be given this file.

**Todo List**
1. After baseline tests pass, apply each of the five weaknesses above with minimal, targeted edits.
2. Confirm that the existing test suite still passes (the tests don't cover the vulnerable paths).
3. Write `docs/VULNERABILITIES_GROUND_TRUTH.md` describing each weakness (location, category,
   expected fix).

**Relevant Context**
- Weaknesses are introduced AFTER the baseline is verified — this keeps the git history clean
  and makes the before/after comparison meaningful for the demo.

---

### Sub-Task 8 — Security requirements document

**Status:** [ ] pending

**Intent**
Write a formal security requirements document that the Security Requirements Analyst subagent
will use to compare requirements against the implementation. This demonstrates Bob's document
understanding capability.

**Expected Outcomes**
- `docs/SECURITY_REQUIREMENTS.md` contains at minimum the following requirement IDs:
  `AUTH-001` through `AUTH-004`, `AUTHZ-001` through `AUTHZ-002`, `INPUT-001`, `ERROR-001`,
  `CONFIG-001`, `TEST-001` through `TEST-003`.
- Every requirement has: ID, title, description, acceptance criteria, and relevant code area.

**Todo List**
1. Write `docs/SECURITY_REQUIREMENTS.md` with all requirement entries.
2. Ensure requirements map directly to the intentional weaknesses so the analyst can find
   violations by comparing the document to the code.

**Relevant Context**
- Requirements should be phrased as obligations ("The application MUST …") to make
  compliance checking unambiguous.
- This document is created BEFORE the SecureReview Copilot workflow runs so the analyst
  treats it as the source of truth.

---

### Sub-Task 9 — README and run instructions

**Status:** [ ] pending

**Intent**
Update the README so any judge can clone, install, and run the application and tests in under
two minutes.

**Expected Outcomes**
- `README.md` contains: project overview, quick-start (virtualenv + pip install + uvicorn),
  test command (`pytest`), environment variables reference, and a pointer to the security
  requirements document.

**Todo List**
1. Rewrite the project-level `README.md` with the above sections.

**Relevant Context**
- Keep the existing `SECURITY.MD` unchanged — it is the hackathon template's credential guidance.

---

## Phase 4–10 — SecureReview Copilot Workflow (Planned, not yet implemented)

These phases are described here for planning purposes. They will be specified in detail in
separate plan files once the baseline application (Phases 1–3) is complete.

### Phase 4 — SecureReview Copilot workflow scaffold
- A Bob custom mode or prompt that triggers the full review pipeline.
- Coordinates all subagents.
- Bob capabilities: Agent mode, parallel task coordination.

### Phase 5 — Parallel subagents
Four independent subagents that analyse the codebase simultaneously:
1. **Security Analyst** — finds vulnerabilities by inspecting auth, authz, SQL, config, error handling.
2. **Testing Analyst** — inspects existing tests, identifies missing coverage and edge cases.
3. **Code Quality Analyst** — identifies maintainability issues and unsafe assumptions.
4. **Security Requirements Analyst** — reads `docs/SECURITY_REQUIREMENTS.md` and checks each requirement against the implementation.
- Bob capabilities: `spawn_subagent`, parallel execution, document understanding.

### Phase 6 — Finding consolidation
- Main agent merges outputs from all four analysts.
- Deduplicates overlapping findings.
- Produces `docs/FINDINGS_CONSOLIDATED.md`.
- Bob capabilities: document synthesis, structured output.

### Phase 7 — Remediation and testing
- Bob creates a prioritised `docs/REMEDIATION_PLAN.md`.
- After approval, implements minimal targeted fixes.
- Generates or updates regression tests.
- Runs full test suite and records results.
- Bob capabilities: code modification, test execution, diagnostic loop.

### Phase 8 — Independent verification
- A separate **Security Verification Critic** subagent that has NOT seen the original analysis.
- Independently verifies that each finding is fixed, no regression was introduced, and no new issues appeared.
- Bob capabilities: independent `spawn_subagent`, critical evaluation.

### Phase 9 — Final report
- Generates `docs/SECURITY_REVIEW_FINAL.md` with executive summary, all findings, remediation evidence, test results, and requirement compliance table.
- Bob capabilities: document generation, structured reporting.

### Phase 10 — Measurement and demo
- Records metrics: analysis tasks automated, issues found vs ground truth, tests created, review time, manual steps eliminated.
- Prepares a step-by-step demo script.
- Calculates detection accuracy against `docs/VULNERABILITIES_GROUND_TRUTH.md`.

---

## Implementation Sequencing

```
Sub-Task 1 (scaffold)
  └─> Sub-Task 2 (database)
        └─> Sub-Task 3 (models)
              └─> Sub-Task 4 (auth)
                    └─> Sub-Task 5 (users)
                          └─> Sub-Task 6 (products)
                                ├─> Sub-Task 7 (vulnerabilities)
                                └─> Sub-Task 8 (security requirements doc)
                                      └─> Sub-Task 9 (README)
```

Each sub-task targets a distinct module. They are designed to be handed to Agent mode one at a
time, with the developer verifying tests pass between each step.

---

## Verification Gate

After Sub-Tasks 1–6 are complete (before introducing weaknesses):
- `pytest` must pass with zero failures.
- `GET /health` must return `{"status": "ok"}`.
- Registration, login, and a protected product creation must succeed via `httpx` or manual curl.

After Sub-Task 7 (weaknesses introduced):
- The same test suite must still pass (confirming the weaknesses are undetected by current tests).
- The ground-truth document must be committed.

---
