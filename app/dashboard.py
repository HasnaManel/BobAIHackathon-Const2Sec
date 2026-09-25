"""Security Gate Dashboard API.

Provides endpoints that back the web dashboard:
  GET  /gate/status          — current project / pipeline status
  POST /gate/analyze         — trigger a simulated security analysis run
  POST /gate/fix             — trigger a simulated fix run
  POST /gate/test            — trigger a simulated test run
  GET  /gate/report          — return the latest final report summary

All state is stored in-process (a simple dict) so no DB migration is needed.
This is intentionally a demo/hackathon implementation.
"""

import time
from typing import Any

from fastapi import APIRouter
from pydantic import BaseModel

router = APIRouter(prefix="/gate", tags=["dashboard"])

# ---------------------------------------------------------------------------
# In-process state
# ---------------------------------------------------------------------------

_INITIAL_STATE: dict[str, Any] = {
    "project_name": "SecureGate Demo",
    "phase": "idle",           # idle | analyzing | fixing | testing | done
    "progress": 0,             # 0-100
    "last_run_at": None,
    "security_findings": [],
    "testing_findings": [],
    "quality_findings": [],
    "verification_status": "not_run",   # not_run | passed | failed
    "report": None,
}

_state: dict[str, Any] = dict(_INITIAL_STATE)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

_SECURITY_FINDINGS = [
    {
        "id": "VULN-001",
        "severity": "high",
        "title": "Missing ownership check on DELETE /products/{id}",
        "file": "app/products.py",
        "line": 71,
        "detail": "Any authenticated user can delete any product regardless of ownership.",
        "fixed": False,
    },
    {
        "id": "VULN-002",
        "severity": "medium",
        "title": "No rate limiting on authentication endpoints",
        "file": "app/auth.py",
        "line": 135,
        "detail": "Brute-force attacks against /auth/login are unrestricted.",
        "fixed": False,
    },
    {
        "id": "VULN-003",
        "severity": "medium",
        "title": "Username enumeration via distinct error messages",
        "file": "app/auth.py",
        "line": 145,
        "detail": "'User not found' vs 'Incorrect password' leaks valid usernames.",
        "fixed": False,
    },
    {
        "id": "VULN-004",
        "severity": "high",
        "title": "Hardcoded JWT signing key fallback",
        "file": "app/auth.py",
        "line": 28,
        "detail": "APP_SIGNING_KEY defaults to 'changeme', enabling token forgery.",
        "fixed": False,
    },
]

_TESTING_FINDINGS = [
    {
        "id": "TEST-001",
        "severity": "low",
        "title": "No negative-path test for ownership enforcement",
        "file": "tests/test_products.py",
        "detail": "DELETE by non-owner is not tested — VULN-001 went undetected.",
        "fixed": False,
    },
    {
        "id": "TEST-002",
        "severity": "low",
        "title": "No brute-force / rate-limit test",
        "file": "tests/test_auth.py",
        "detail": "Rapid login attempts are not covered in the test suite.",
        "fixed": False,
    },
]

_QUALITY_FINDINGS = [
    {
        "id": "QUAL-001",
        "severity": "info",
        "title": "Inline SQL strings could use parameterised query helpers",
        "file": "app/products.py",
        "detail": "Low risk here (params are used), but a helper layer improves readability.",
        "fixed": False,
    },
    {
        "id": "QUAL-002",
        "severity": "info",
        "title": "No structured logging — only implicit stdout",
        "file": "app/main.py",
        "detail": "Production deployments need structured log output for observability.",
        "fixed": False,
    },
]


# ---------------------------------------------------------------------------
# Response models
# ---------------------------------------------------------------------------

class StatusResponse(BaseModel):
    project_name: str
    phase: str
    progress: int
    last_run_at: str | None
    security_findings: list[dict]
    testing_findings: list[dict]
    quality_findings: list[dict]
    verification_status: str
    report: dict | None


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------

@router.get("/status", response_model=StatusResponse)
def get_status():
    """Return current pipeline state."""
    return StatusResponse(**_state)


@router.post("/analyze")
def analyze():
    """Simulate a full analysis pass by all three subagents."""
    global _state
    _state = {
        **_INITIAL_STATE,
        "project_name": _state["project_name"],
        "phase": "analyzing",
        "progress": 100,
        "last_run_at": _fmt_now(),
        "security_findings": [dict(f) for f in _SECURITY_FINDINGS],
        "testing_findings": [dict(f) for f in _TESTING_FINDINGS],
        "quality_findings": [dict(f) for f in _QUALITY_FINDINGS],
        "verification_status": "not_run",
        "report": None,
    }
    return {"message": "Analysis complete", "phase": "analyzing"}


@router.post("/fix")
def fix_issues():
    """Simulate the fix subagent patching high/medium findings."""
    if not _state["security_findings"]:
        return {"message": "No findings to fix — run analysis first."}

    for f in _state["security_findings"]:
        if f["severity"] in ("high", "medium"):
            f["fixed"] = True
    for f in _state["testing_findings"]:
        f["fixed"] = True

    _state["phase"] = "fixing"
    _state["progress"] = 100
    return {"message": "High and medium severity issues patched."}


@router.post("/test")
def run_tests():
    """Simulate the test subagent verifying fixes."""
    all_fixed = all(
        f["fixed"] for f in _state["security_findings"] if f["severity"] in ("high", "medium")
    )
    _state["phase"] = "testing"
    _state["verification_status"] = "passed" if all_fixed else "failed"
    _state["progress"] = 100
    return {
        "message": "Tests complete.",
        "verification_status": _state["verification_status"],
    }


@router.get("/report")
def get_report():
    """Generate and return the final security report."""
    sf = _state["security_findings"]
    tf = _state["testing_findings"]
    qf = _state["quality_findings"]

    open_high = sum(1 for f in sf if f["severity"] == "high" and not f["fixed"])
    open_medium = sum(1 for f in sf if f["severity"] == "medium" and not f["fixed"])
    fixed_count = sum(1 for f in sf if f["fixed"]) + sum(1 for f in tf if f["fixed"])

    _state["phase"] = "done"
    _state["report"] = {
        "generated_at": _fmt_now(),
        "project": _state["project_name"],
        "open_high": open_high,
        "open_medium": open_medium,
        "fixed": fixed_count,
        "quality_notes": len(qf),
        "verification": _state["verification_status"],
        "summary": (
            "✅ All critical issues resolved — project is ready for review."
            if open_high == 0 and open_medium == 0
            else f"⚠️ {open_high} high and {open_medium} medium issues remain open."
        ),
    }
    return _state["report"]


# ---------------------------------------------------------------------------
# Utility
# ---------------------------------------------------------------------------

def _fmt_now() -> str:
    t = time.gmtime()
    return (
        f"{t.tm_year}-{t.tm_mon:02d}-{t.tm_mday:02d} "
        f"{t.tm_hour:02d}:{t.tm_min:02d}:{t.tm_sec:02d} UTC"
    )
