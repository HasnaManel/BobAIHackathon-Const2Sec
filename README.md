# SecureReview Copilot — IBM Bob Hackathon

**SecureReview Copilot** is an agentic developer workflow built on IBM Bob 2.0
that automates the manual software security review process.

This repository contains:

| Path | Purpose |
|------|---------|
| `app/` | **SecureGate** — target Python/FastAPI application |
| `docs/SECURITY_REQUIREMENTS.md` | Formal security requirements (used by the review agents) |
| `docs/VULNERABILITIES_GROUND_TRUTH.md` | Evaluation ground truth (**not shown to agents**) |
| `tests/` | pytest test suite |
| `security-gate-plan.md` | Full implementation plan |

---

## SecureGate — the demo application

SecureGate is a small FastAPI + SQLite REST API that provides:

- User registration and login (JWT authentication)
- User profile endpoints (authenticated, ownership-enforced)
- Product catalogue API (public reads, protected writes/deletes)
- Admin seed script for local demos

It intentionally contains a small number of realistic security weaknesses that
the SecureReview Copilot workflow will detect, remediate, and verify.

---

## Quick start

### Prerequisites

- Python 3.11+
- A terminal

### 1 — Clone and install

```bash
git clone <repo-url>
cd BobAIHackathon-Const2Sec
python -m venv .venv
# Windows:
.venv\Scripts\activate
# macOS / Linux:
source .venv/bin/activate

pip install -r requirements.txt
```

### 2 — Configure environment

```bash
# Windows PowerShell:
$env:APP_SIGNING_KEY = (python -c "import secrets; print(secrets.token_hex(32))")

# macOS / Linux:
export APP_SIGNING_KEY=$(python -c "import secrets; print(secrets.token_hex(32))")
```

See `env.example` for all available variables.

### 3 — Seed the admin account (optional, for demo)

```bash
python -m app.seed
```

This generates a random admin password and prints it once.
Save it — it will not be shown again.

### 4 — Run the API server

```bash
python -m uvicorn app.main:app --reload
```

API is available at <http://localhost:8000>  
Interactive docs: <http://localhost:8000/docs>

### 5 — Run the tests

```bash
pytest tests/ -v
```

Expected result: **28 tests pass, 0 fail.**

### 6 — Run the smoke test (optional)

Start the server first (`uvicorn app.main:app --port 8765`), then:

```bash
python smoke_test.py
```

---

## API reference

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| GET | `/health` | None | Health check |
| POST | `/auth/register` | None | Register a new user |
| POST | `/auth/login` | None | Login, returns JWT |
| GET | `/users/me` | Bearer | Own profile |
| GET | `/users/{id}` | Bearer | Public profile (full for admins) |
| PUT | `/users/me` | Bearer | Update own email |
| GET | `/products` | None | List all products |
| GET | `/products/{id}` | None | Get a product |
| POST | `/products` | Bearer | Create a product |
| DELETE | `/products/{id}` | Bearer | Delete a product |

---

## Environment variables

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `APP_SIGNING_KEY` | Yes | — (fails at startup) | JWT signing secret |
| `APP_DATABASE_PATH` | No | `securegate.db` | SQLite file path |
| `APP_TOKEN_MINUTES` | No | `30` | JWT expiry in minutes |

---

## Security requirements

See [`docs/SECURITY_REQUIREMENTS.md`](docs/SECURITY_REQUIREMENTS.md) for the
formal security requirements used during the SecureReview Copilot analysis.

---

## Hackathon workflow overview

```
Developer asks Bob to review a code change
          ↓
    IBM Bob Agent (coordinator)
          ↓
    ┌─────────────────────────────────────┐
    │  Parallel subagents                 │
    │  ├── Security Analyst               │
    │  ├── Testing Analyst                │
    │  ├── Code Quality Analyst           │
    │  └── Security Requirements Analyst  │
    └─────────────────────────────────────┘
          ↓
    Consolidate findings
          ↓
    Remediation plan → Implement fixes
          ↓
    Generate/update tests → Run tests
          ↓
    Independent Security Verification Agent
          ↓
    docs/SECURITY_REVIEW_FINAL.md
```
