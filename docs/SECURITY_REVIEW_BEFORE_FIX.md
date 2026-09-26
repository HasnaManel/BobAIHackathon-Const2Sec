# SecureGate — Security Review (Before Fix)

## Summary

This report documents the findings of a multi-domain security review of the SecureGate
repository. Five specialist agents independently analysed the codebase under `app/` and
`tests/`. Findings are graded **critical / high / medium / low / info**.

| ID        | Severity | Title                                                            | File                     |
|-----------|----------|------------------------------------------------------------------|--------------------------|
| FIND-001  | high     | Unauthenticated access to all /gate/* endpoints                  | app/dashboard.py         |
| FIND-002  | high     | Bob CLI invoked with `--trust` flag                              | app/bob_runner.py        |
| FIND-003  | medium   | Rate limiter keyed on raw `request.client.host` (proxy-bypassable) | app/auth.py            |
| FIND-004  | medium   | `python-dotenv` missing from requirements.txt                    | requirements.txt         |
| FIND-005  | medium   | Real database file `securegate.db` committed to the repository   | securegate.db            |
| FIND-006  | medium   | Race condition / contradictory assertions in gate analyze test    | tests/test_gate.py       |
| FIND-007  | medium   | Test inserts user into real on-disk database                     | tests/test_bob_runner.py |
| FIND-008  | medium   | No test that `require_admin` rejects regular users with 403      | tests/test_users.py      |
| FIND-009  | low      | `bob run` prompt whitelist not enforced at function boundary     | app/bob_runner.py        |
| FIND-010  | low      | `price` field uses `float` type for monetary value               | app/models.py            |
| FIND-011  | low      | No maximum price constraint on `ProductCreate`                   | app/models.py            |
| FIND-012  | low      | `foreign_keys` PRAGMA not set in `init_db()` connection          | app/database.py          |
| FIND-013  | low      | `BOB_API_KEY` not validated at application startup               | app/bob_runner.py        |
| FIND-014  | low      | `APP_TOKEN_MINUTES` has no upper bound validation                | app/auth.py              |
| FIND-015  | low      | `PUT /users/me` missing unauthenticated-request test             | tests/test_users.py      |
| FIND-016  | low      | Login test accepts 404 masking a missing-router regression       | tests/test_auth.py       |

---

### FIND-001

**ID:** FIND-001
**Severity:** high
**Title:** Unauthenticated access to all /gate/* endpoints
**File:** app/dashboard.py
**Line:** 325
**Detail:** The endpoints `POST /gate/analyze`, `POST /gate/fix`, `POST /gate/test`, and `GET /gate/report` carry no authentication dependency. Any anonymous HTTP client can trigger a full Bob LLM run (compute-intensive, potentially billable), cause source-code modifications via the fix agent, or run the test suite. Only a `BOB_API_KEY` absence check prevents abuse, and that check occurs inside the background thread — the 202 response has already been sent.
**Remediation:** Add an `Annotated[sqlite3.Row, Depends(require_admin)]` (or at minimum `Depends(get_current_user)`) parameter to each `/gate/*` mutating endpoint. For the hackathon demo at minimum protect with a shared secret header checked before spawning the background thread.

---

### FIND-002

**ID:** FIND-002
**Severity:** high
**Title:** Bob CLI invoked with `--trust` flag (auto-approves all tool use)
**File:** app/bob_runner.py
**Line:** 101
**Detail:** `cmd = [_BOB_EXECUTABLE, "run", "--trust", prompt]` — the `--trust` flag disables Bob's interactive safety confirmations and auto-approves every tool call (file reads, writes, shell commands). When combined with FIND-001 (unauthenticated trigger), any anonymous caller can cause Bob to execute arbitrary file-system and shell operations without any human approval step.
**Remediation:** Remove `--trust` unless the pipeline is running in a fully sandboxed environment. If auto-approval is required for CI/CD use, gate it behind authentication (FIND-001) and restrict the Bob workspace permissions at the OS level.

---

### FIND-003

**ID:** FIND-003
**Severity:** medium
**Title:** Rate limiter keyed on raw `request.client.host` — bypassable behind a proxy
**File:** app/auth.py
**Line:** 70
**Detail:** `ip = request.client.host if request.client else "unknown"` reads the TCP peer address. Behind a reverse proxy (nginx, AWS ALB, Cloudflare) all requests share the single proxy IP, making the rate limiter useless. An attacker on the internet who routes through a proxy also trivially bypasses the limit by rotating proxy IPs.
**Remediation:** Read the client IP from `X-Forwarded-For` (first entry) or `X-Real-IP` headers when a trusted proxy is configured, using a configurable `TRUSTED_PROXY_IPS` list. Consider a library such as `slowapi` which integrates with FastAPI and handles proxy headers correctly.

---

### FIND-004

**ID:** FIND-004
**Severity:** medium
**Title:** `python-dotenv` missing from `requirements.txt`
**File:** requirements.txt
**Line:** null
**Detail:** `app/auth.py` lines 24–26 execute `from dotenv import load_dotenv; load_dotenv()`. The package `python-dotenv` is not listed in `requirements.txt`. A fresh install (`pip install -r requirements.txt`) will fail with `ModuleNotFoundError: No module named 'dotenv'` before the application can start, or the application will silently skip `.env` loading if `python-dotenv` happens to be present from another package's transitive dependency.
**Remediation:** Add `python-dotenv>=1.0.0` to `requirements.txt`.

---

### FIND-005

**ID:** FIND-005
**Severity:** medium
**Title:** Real database file `securegate.db` committed to version control
**File:** securegate.db
**Line:** null
**Detail:** A live SQLite database file is present at the repository root and tracked by git. This file may contain seeded user records including hashed passwords and email addresses. Any developer who clones the repository receives a copy of the database. Historical git objects may additionally preserve previous database states that are otherwise thought deleted.
**Remediation:** Add `securegate.db` to `.gitignore`, remove the file from tracking with `git rm --cached securegate.db`, and purge it from git history with `git filter-branch` or `git filter-repo`.

---

### FIND-006

**ID:** FIND-006
**Severity:** medium
**Title:** Race condition in `test_analyze_populates_both_finding_lists` — contradictory assertions
**File:** tests/test_gate.py
**Line:** 268
**Detail:** The test calls `POST /gate/analyze` which starts a background `threading.Thread`. It then immediately calls `GET /gate/status`. The assertion on line 273 checks `status["phase"] == "analyzing"` (implying the thread has not finished) while line 274–275 check `status["progress"] == 100` (implying the thread has finished). These two assertions are mutually contradictory. The test will be flaky depending on thread scheduling: it passes when the thread finishes before the status poll and fails otherwise.
**Remediation:** Either (a) patch `run_bob` to be synchronous and verify the final `"done"` phase, or (b) add a short polling loop until `phase == "done"` before checking progress. Remove the contradictory `phase == "analyzing"` assertion.

---

### FIND-007

**ID:** FIND-007
**Severity:** medium
**Title:** `TestGateTestNoneStdout` writes to real on-disk database, not test fixture
**File:** tests/test_bob_runner.py
**Line:** 248
**Detail:** The test calls `get_db()` directly without going through the `dependency_overrides` set up by the `client` fixture. This opens a connection to the real `securegate.db` on disk and inserts a user row (`nulltest_admin`). Repeated test runs accumulate state in the developer database, the on-conflict clause silently masks the issue, and CI pipelines that share a clean checkout may have different behavior depending on whether the db file exists.
**Remediation:** Use the `client` fixture (which sets `dependency_overrides[get_db]`) and the in-memory DB, or explicitly connect to `:memory:` inside this test.

---

### FIND-008

**ID:** FIND-008
**Severity:** medium
**Title:** No test verifying `require_admin` rejects regular users with HTTP 403
**File:** tests/test_users.py
**Line:** null
**Detail:** The `require_admin` dependency is defined in `app/auth.py` and would be the primary guard for any admin-only route. No test in the test suite calls an admin-only endpoint as a regular (non-admin) authenticated user and asserts a `403 Forbidden` response. If the `require_admin` dependency is accidentally removed or bypassed, no test would catch the regression.
**Remediation:** Add a test that authenticates as a regular user, calls an admin-only endpoint (e.g., a hypothetical admin route or the `GET /users/{id}` with admin-only fields), and asserts `403`.

---

### FIND-009

**ID:** FIND-009
**Severity:** low
**Title:** `run_bob()` has no prompt whitelist enforced at the function boundary
**File:** app/bob_runner.py
**Line:** 75
**Detail:** The docstring at line 80–81 states "Must be one of the four values defined in _ALLOWED_PROMPTS (enforced by the callers in dashboard.py — this function itself does not whitelist)." There is no `_ALLOWED_PROMPTS` constant defined anywhere in the file; the promised allowlist does not exist. If new callers are added or `run_bob` is called directly in tests, arbitrary prompt strings reach the Bob subprocess.
**Remediation:** Define a `frozenset` of allowed prompt strings in `bob_runner.py` and validate against it at the start of `run_bob()`, raising `ValueError` for unrecognised prompts.

---

### FIND-010

**ID:** FIND-010
**Severity:** low
**Title:** `price` field uses `float` type for monetary value
**File:** app/models.py
**Line:** 66
**Detail:** `price: float = Field(..., gt=0)` stores prices as IEEE 754 double-precision floating-point. Binary floats cannot represent many decimal fractions exactly (e.g., `0.1 + 0.2 == 0.30000000000000004`). For a product price field this can cause display rounding errors or incorrect arithmetic in downstream calculations.
**Remediation:** Use `Decimal` with `condecimal(gt=0, max_digits=12, decimal_places=2)` for the Pydantic model, and store as `TEXT` in SQLite (or as an integer number of cents).

---

### FIND-011

**ID:** FIND-011
**Severity:** low
**Title:** No maximum price constraint on `ProductCreate`
**File:** app/models.py
**Line:** 66
**Detail:** `price: float = Field(..., gt=0)` accepts any positive value with no upper bound. A client can submit `price=9e307`, which is a valid IEEE 754 value and will be stored without error. Downstream display, reporting, or arithmetic could overflow or produce nonsensical output.
**Remediation:** Add `lt=1_000_000` (or an appropriate domain maximum) to the `Field` definition.

---

### FIND-012

**ID:** FIND-012
**Severity:** low
**Title:** `PRAGMA foreign_keys = ON` not set in `init_db()` connection
**File:** app/database.py
**Line:** 43
**Detail:** `get_db()` correctly enables `PRAGMA foreign_keys = ON` on every request connection. However, `init_db()` opens its own `sqlite3.connect()` (line 43) and never enables foreign keys. SQLite foreign key enforcement is per-connection and defaults to OFF. Any operation performed during `init_db()` — or by the seed script — will not enforce `ON DELETE CASCADE` or other referential constraints.
**Remediation:** Add `conn.execute("PRAGMA foreign_keys = ON")` immediately after `sqlite3.connect()` in `init_db()`, and likewise in `seed.py`.

---

### FIND-013

**ID:** FIND-013
**Severity:** low
**Title:** `BOB_API_KEY` not validated at application startup
**File:** app/bob_runner.py
**Line:** 88
**Detail:** `BOB_API_KEY` is only checked inside `run_bob()` which is called from background threads. The application starts, serves requests, and returns 202 for gate endpoints before the missing-key error is detected. Operators may believe the service is healthy until the first actual Bob run fails silently in a background thread.
**Remediation:** Add a startup check (similar to `APP_SIGNING_KEY` in `auth.py`) that reads `BOB_API_KEY` at import time and logs a prominent warning (or raises `RuntimeError`) if it is absent.

---

### FIND-014

**ID:** FIND-014
**Severity:** low
**Title:** `APP_TOKEN_MINUTES` has no upper bound validation
**File:** app/auth.py
**Line:** 54
**Detail:** `_TOKEN_MINUTES: int = int(os.environ.get("APP_TOKEN_MINUTES", "30"))` — a misconfigured environment (e.g., `APP_TOKEN_MINUTES=999999999`) would issue JWTs that expire decades in the future, effectively making them permanent. There is also no validation that the value is a positive integer greater than zero.
**Remediation:** Add a bounds check: `if not (1 <= _TOKEN_MINUTES <= 1440): raise RuntimeError(...)` (cap at 24 hours for web tokens).

---

### FIND-015

**ID:** FIND-015
**Severity:** low
**Title:** `PUT /users/me` has no unauthenticated-request test
**File:** tests/test_users.py
**Line:** 63
**Detail:** `TestUpdateMyEmail` covers authenticated success and duplicate-email conflict but never issues a `PUT /users/me` without an `Authorization` header. If authentication were accidentally removed from the route, no test would catch the regression.
**Remediation:** Add `test_unauthenticated_update_rejected` that calls `PUT /users/me` without headers and asserts `status_code in (401, 403)`.

---

### FIND-016

**ID:** FIND-016
**Severity:** low
**Title:** Login test accepts HTTP 404 as valid, masking a missing-router regression
**File:** tests/test_auth.py
**Line:** 124
**Detail:** `test_token_grants_access_to_protected_route` asserts `resp.status_code in (200, 404)`. A 404 means the `/users/me` route does not exist, so the test passes even when the users router is not registered. This masks a real regression where valid tokens would correctly receive 200 but the route is missing entirely.
**Remediation:** The users router is now always registered (it is present in `app/main.py`). Change the assertion to `assert resp.status_code == 200` to make the test unconditionally meaningful.
