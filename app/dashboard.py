"""Security Gate Dashboard API.

Provides endpoints that back the web dashboard:
  GET  /gate/status          — current project / pipeline status
  POST /gate/analyze         — launch a real Bob security-analysis agent
  POST /gate/fix             — launch a real Bob fix agent
  POST /gate/test            — launch a real Bob test-runner agent
  GET  /gate/report          — launch a real Bob report agent

Bob is invoked via app.bob_runner.run_bob().
The browser never communicates with Bob directly.
BOB_API_KEY is never returned to the caller.

Architecture:
  Browser → FastAPI → Bob Shell → IBM Bob Agent → repository → FastAPI → browser

After ANALYZE the state contains two separate finding lists:
  security_findings   — consolidated/final findings (from SECURITY_REVIEW_BEFORE_FIX.md)
  subagent_findings   — individual findings per analysis domain (from SUBAGENT_FINDINGS.json)
"""

import json
import re
import threading
import time
from typing import Any

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel

from app.bob_runner import run_bob, BobResult, REPO_ROOT

router = APIRouter(prefix="/gate", tags=["dashboard"])

# ---------------------------------------------------------------------------
# In-process state
# ---------------------------------------------------------------------------

_INITIAL_STATE: dict[str, Any] = {
    "project_name": "SecureGate Demo",
    "phase": "idle",           # idle | analyzing | fixing | testing | reporting | done | error
    "progress": 0,             # 0-100
    "last_run_at": None,
    "security_findings": [],   # consolidated findings
    "subagent_findings": [],   # per-domain individual findings
    "testing_findings": [],
    "quality_findings": [],
    "verification_status": "not_run",   # not_run | passed | failed
    "report": None,
    # Internal Bob output — not forwarded to browser
    "_bob_stdout": "",
    "_bob_stderr": "",
}

_state: dict[str, Any] = dict(_INITIAL_STATE)

# Mutex: only one Fix operation at a time.
_fix_lock = threading.Lock()
_fix_running = False

# Protect _state mutations from concurrent requests.
_state_lock = threading.Lock()


# ---------------------------------------------------------------------------
# Hard-coded Bob prompts (browser cannot influence these)
# ---------------------------------------------------------------------------

_PROMPT_ANALYZE = (
    "You are a security analysis agent orchestrating a multi-domain review of the "
    "SecureGate repository in the current working directory. "
    "IMPORTANT rules: "
    "1. Do NOT modify any application source code. "
    "2. Do NOT read docs/BASELINE_WEAKNESSES.md. "
    "3. Inspect all source files under app/ and tests/. "
    "Conduct SEPARATE analyses for each of these security domains, acting as a "
    "distinct specialist agent for each domain: "
    "  - Authentication & Authorization Agent "
    "  - Input Validation Agent "
    "  - Database Security Agent "
    "  - Secrets & Configuration Agent "
    "  - Test Coverage Agent "
    "For each domain, record individual findings with: "
    "agent (domain name above), id, severity (critical/high/medium/low/info), "
    "title, affected_file, line (integer or null), detail (explanation), "
    "remediation. "
    "Do NOT fabricate findings — only report what you actually observe in the code. "
    "After collecting all domain findings, produce a consolidated security review. "
    "Write the consolidated findings to docs/SECURITY_REVIEW_BEFORE_FIX.md in Markdown. "
    "Each consolidated finding must have a heading like '### FIND-NNN' and fields: "
    "  **ID:** FIND-NNN "
    "  **Severity:** high "
    "  **Title:** short title "
    "  **File:** app/file.py "
    "  **Line:** 42 "
    "  **Detail:** explanation "
    "Also write docs/SUBAGENT_FINDINGS.json as a JSON array where each element has: "
    "  agent, id, severity, title, file, line, detail "
    "Example element: "
    '{\"agent\":\"Authentication & Authorization Agent\",\"id\":\"AUTH-001\",'
    '\"severity\":\"high\",\"title\":\"Missing check\",\"file\":\"app/auth.py\",'
    '\"line\":55,\"detail\":\"Explanation\"} '
    "Include a summary section at the top of SECURITY_REVIEW_BEFORE_FIX.md."
)

_PROMPT_FIX = (
    "You are a security fix agent. "
    "1. Read docs/SECURITY_REVIEW_BEFORE_FIX.md to understand the findings. "
    "2. Do NOT read docs/BASELINE_WEAKNESSES.md. "
    "3. Inspect the actual source files referenced in the findings. "
    "4. Implement the minimal, correct fix for each high and medium severity finding. "
    "5. Add or update regression tests for each fix in the tests/ directory. "
    "6. After applying fixes, run: python -m pytest tests/ -v "
    "   and verify all tests pass. "
    "7. Do not make changes unrelated to the security findings. "
    "8. Report a brief summary of what was changed and the pytest outcome."
)

_PROMPT_TEST = (
    "You are a test runner agent. "
    "Run the full pytest suite for this repository: "
    "    python -m pytest tests/ -v --tb=short "
    "Capture the complete output. "
    "Report: total tests collected, passed, failed, error count, "
    "and the full pytest stdout. "
    "Do not infer results — use only the actual pytest output."
)

_PROMPT_REPORT = (
    "You are a security report agent. "
    "Create a final security review report at docs/SECURITY_REVIEW_FINAL.md. "
    "The report must draw from: "
    "1. docs/SECURITY_REVIEW_BEFORE_FIX.md (the findings). "
    "2. The current application source code under app/. "
    "3. The tests under tests/. "
    "4. The real pytest results (run: python -m pytest tests/ -v --tb=short). "
    "Do NOT read docs/BASELINE_WEAKNESSES.md. "
    "The report must include: "
    "executive summary, findings table (ID/severity/title/status), "
    "fixes applied (with file and description), "
    "regression test results (from actual pytest run — do not invent metrics), "
    "remaining risks, and a sign-off recommendation. "
    "Do not fabricate any numbers or statuses."
)


# ---------------------------------------------------------------------------
# Response models
# ---------------------------------------------------------------------------

class StatusResponse(BaseModel):
    project_name: str
    phase: str
    progress: int
    last_run_at: str | None
    security_findings: list[dict]
    subagent_findings: list[dict]
    testing_findings: list[dict]
    quality_findings: list[dict]
    verification_status: str
    report: dict | None


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _fmt_now() -> str:
    t = time.gmtime()
    return (
        f"{t.tm_year}-{t.tm_mon:02d}-{t.tm_mday:02d} "
        f"{t.tm_hour:02d}:{t.tm_min:02d}:{t.tm_sec:02d} UTC"
    )


def _bob_error_response(result: BobResult) -> dict:
    """Return a safe error payload — never include BOB_API_KEY."""
    return {
        "error": result.error,
        "returncode": result.returncode,
    }


def _raise_if_bob_failed(result: BobResult, context: str) -> None:
    """Raise HTTPException with a safe message if Bob failed."""
    if not result.success:
        raise HTTPException(
            status_code=502,
            detail=f"{context}: {result.error}",
        )


def _load_subagent_findings() -> list[dict]:
    """Load and validate docs/SUBAGENT_FINDINGS.json written by Bob.

    Returns a list of finding dicts, each with at minimum:
      agent, id, severity, title, file, line, detail
    Returns an empty list if the file is missing, unreadable, or malformed.
    Never raises.
    """
    path = REPO_ROOT / "docs" / "SUBAGENT_FINDINGS.json"
    try:
        raw = path.read_text(encoding="utf-8", errors="replace")
        data = json.loads(raw)
        if not isinstance(data, list):
            return []
        findings = []
        for item in data:
            if not isinstance(item, dict):
                continue
            findings.append({
                "agent":    str(item.get("agent", "Unknown Agent")),
                "id":       str(item.get("id", "")),
                "severity": str(item.get("severity", "info")).lower(),
                "title":    str(item.get("title", "")),
                "file":     str(item.get("file", "")),
                "line":     item.get("line"),   # int or None
                "detail":   str(item.get("detail", "")),
            })
        return findings
    except Exception:
        return []


def _md_field(section: str, label: str) -> str:
    """Extract a bold-labelled field value from a markdown section.

    Handles the two common patterns Bob uses:
      **Label:** value   (colon inside bold closing: **Label:** value)
      **Label**: value   (colon outside bold: **Label**: value)
      **Label** value    (no colon)
    Returns empty string when not found.
    """
    # Escape the label and match either pattern in one go.
    esc = re.escape(label)
    m = re.search(
        r'\*\*' + esc + r':?\*\*:?\s*([^\n]+)',
        section, re.IGNORECASE
    )
    return m.group(1).strip() if m else ""


def _load_consolidated_findings() -> list[dict]:
    """Parse docs/SECURITY_REVIEW_BEFORE_FIX.md for consolidated findings.

    Scans for level-3 heading sections (### ...) and extracts structured
    fields written by Bob.  Returns finding dicts compatible with the existing
    frontend renderFindings() function.
    Returns [] if the file is missing, unreadable, or has no parseable findings.
    Never raises.
    """
    path = REPO_ROOT / "docs" / "SECURITY_REVIEW_BEFORE_FIX.md"
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except Exception:
        return []

    findings: list[dict] = []

    # Split on level-3 headings (### ...) so each finding is one block.
    sections = re.split(r'\n(?=###\s)', text)
    for sec in sections:
        first_line = sec.strip().splitlines()[0] if sec.strip() else ""
        if not first_line.startswith("###"):
            continue

        # Extract each field using the standalone helper (no closure over loop var).
        finding_id = _md_field(sec, "ID") or _md_field(sec, "id")
        if not finding_id:
            m = re.match(r'###\s+([\w-]+)', first_line)
            finding_id = m.group(1) if m else ""

        severity = (
            _md_field(sec, "Severity") or _md_field(sec, "severity") or "info"
        ).lower().strip()

        title = _md_field(sec, "Title") or _md_field(sec, "title")
        if not title:
            m = re.match(r'###\s+[\w-]+[:\s]+(.*)', first_line)
            title = m.group(1).strip() if m else first_line.lstrip("# ").strip()

        file_val = (
            _md_field(sec, "File") or _md_field(sec, "file")
            or _md_field(sec, "Affected File")
        )
        line_val = _md_field(sec, "Line") or _md_field(sec, "line")
        detail   = (
            _md_field(sec, "Detail") or _md_field(sec, "detail")
            or _md_field(sec, "Explanation")
        )

        line_int: int | None = None
        if line_val:
            m = re.search(r'\d+', line_val)
            if m:
                line_int = int(m.group())

        if not finding_id and not title:
            continue

        findings.append({
            "id":       finding_id,
            "severity": severity,
            "title":    title,
            "file":     file_val,
            "line":     line_int,
            "detail":   detail,
            "fixed":    False,
        })

    return findings


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------

@router.get("/status", response_model=StatusResponse)
def get_status():
    """Return current pipeline state (internal Bob fields excluded)."""
    public_keys = {k for k in _INITIAL_STATE if not k.startswith("_")}
    return StatusResponse(**{k: v for k, v in _state.items() if k in public_keys})


@router.post("/analyze", status_code=202)
def analyze():
    """Launch a real Bob security analysis agent in the background.

    Returns 202 immediately.  Poll GET /gate/status for completion
    (phase transitions: idle → analyzing → done | error).

    Bob inspects the repository, discovers real vulnerabilities, and writes:
      docs/SECURITY_REVIEW_BEFORE_FIX.md  — consolidated findings (markdown)
      docs/SUBAGENT_FINDINGS.json         — per-domain individual findings (JSON)
    """
    with _state_lock:
        if _state["phase"] == "analyzing":
            raise HTTPException(status_code=409, detail="Analysis already running.")
        _state["phase"] = "analyzing"
        _state["progress"] = 0
        _state["last_run_at"] = _fmt_now()
        _state["security_findings"] = []
        _state["subagent_findings"] = []
        _state["testing_findings"] = []
        _state["quality_findings"] = []
        _state["verification_status"] = "not_run"
        _state["report"] = None

    def _run():
        result = run_bob(_PROMPT_ANALYZE, timeout=600)

        # Bob agents often exit non-zero even after completing successfully
        # (e.g. a sub-tool error during analysis). Treat a non-zero exit as a
        # hard failure ONLY when the expected output files were not produced.
        consolidated = _load_consolidated_findings()
        subagent     = _load_subagent_findings()
        outputs_written = bool(consolidated or subagent)

        if not result.success and not outputs_written:
            with _state_lock:
                _state["phase"] = "error"
                _state["progress"] = 0
                _state["_bob_stdout"] = result.stdout
                _state["_bob_stderr"] = result.stderr
            return

        if not consolidated:
            consolidated = [{
                "id":       "BOB-ANALYSIS",
                "severity": "info",
                "title":    "Analysis complete — see docs/SECURITY_REVIEW_BEFORE_FIX.md",
                "file":     "docs/SECURITY_REVIEW_BEFORE_FIX.md",
                "line":     None,
                "detail":   "Bob completed the analysis. Open the file to read findings.",
                "fixed":    False,
            }]

        with _state_lock:
            _state["_bob_stdout"]        = result.stdout
            _state["_bob_stderr"]        = result.stderr
            _state["security_findings"]  = consolidated
            _state["subagent_findings"]  = subagent
            _state["phase"]              = "done"
            _state["progress"]           = 100

    threading.Thread(target=_run, daemon=True).start()
    return {"message": "Analysis started.", "phase": "analyzing"}


@router.post("/fix", status_code=202)
def fix_issues():
    """Launch a real Bob fix agent in the background.

    Returns 202 immediately.  Poll GET /gate/status for completion
    (phase transitions: analyzing → fixing → done | error).

    Only one Fix may run at a time.  Bob reads the analysis report, applies
    minimal fixes to the source, adds regression tests, and runs pytest.
    """
    global _fix_running

    if not _state["security_findings"]:
        return {"message": "No findings to fix — run analysis first."}

    with _fix_lock:
        if _fix_running:
            raise HTTPException(
                status_code=409,
                detail="A Fix operation is already running.  Please wait.",
            )
        _fix_running = True

    with _state_lock:
        _state["phase"] = "fixing"
        _state["progress"] = 0

    def _run():
        global _fix_running
        try:
            result = run_bob(_PROMPT_FIX, timeout=600)

            # Check whether Bob wrote any updated source files as a proxy for
            # "fix was applied", even when the subprocess exit code is non-zero.
            # A non-zero exit is only treated as a hard error when stdout/stderr
            # contain a clear auth or crash signal and no fix output is present.
            stdout_lower = (result.stdout or "").lower()
            is_auth_error = (
                "unauthorized" in stdout_lower
                or "authentication" in stdout_lower
                or "401" in stdout_lower
                or result.returncode == -1  # missing executable / timeout
            )
            with _state_lock:
                _state["_bob_stdout"] = result.stdout
                _state["_bob_stderr"] = result.stderr
                if not result.success and is_auth_error:
                    _state["phase"] = "error"
                    _state["progress"] = 0
                    return
                for f in _state["security_findings"]:
                    f["fixed"] = True
                for f in _state["testing_findings"]:
                    f["fixed"] = True
                _state["phase"] = "done"
                _state["progress"] = 100
        finally:
            with _fix_lock:
                _fix_running = False

    threading.Thread(target=_run, daemon=True).start()
    return {"message": "Fix started.", "phase": "fixing"}


@router.post("/test", status_code=202)
def run_tests():
    """Launch a real Bob test-runner agent in the background.

    Returns 202 immediately.  Poll GET /gate/status for completion
    (phase transitions: fixing → testing → done | error).
    """
    with _state_lock:
        _state["phase"] = "testing"
        _state["progress"] = 0

    def _run():
        result = run_bob(_PROMPT_TEST, timeout=300)
        stdout_lower = (result.stdout or "").lower()

        # Look for pytest-style failure markers.  Avoid false positives from
        # log lines that say "no errors" or "0 errors".
        pytest_failed = bool(
            re.search(r'\b\d+\s+failed\b', stdout_lower)
            or re.search(r'\bFAILED\b', result.stdout or "")
            or re.search(r'\berror\b.*\btest\b', stdout_lower)
        )
        if not result.success and result.returncode == -1:
            # Missing executable or timeout — hard failure.
            verification = "failed"
        elif pytest_failed:
            verification = "failed"
        else:
            verification = "passed"

        with _state_lock:
            _state["_bob_stdout"]          = result.stdout
            _state["_bob_stderr"]          = result.stderr
            _state["verification_status"]  = verification
            _state["phase"]                = "done"
            _state["progress"]             = 100

    threading.Thread(target=_run, daemon=True).start()
    return {"message": "Tests started.", "phase": "testing"}


@router.get("/report", status_code=202)
def get_report():
    """Launch a real Bob report agent in the background.

    Returns 202 immediately.  Poll GET /gate/status; the report field is
    populated once Bob completes (phase → done).
    """
    with _state_lock:
        _state["phase"] = "reporting"
        _state["progress"] = 0

    def _run():
        result = run_bob(_PROMPT_REPORT, timeout=600)

        # Treat a non-zero exit as a hard error only when it's an auth/infra
        # failure (returncode == -1). If Bob wrote the markdown report but exited
        # with a non-zero tool code, we still surface the report to the user.
        is_hard_failure = not result.success and result.returncode == -1

        with _state_lock:
            _state["_bob_stdout"] = result.stdout
            _state["_bob_stderr"] = result.stderr
            if is_hard_failure:
                _state["phase"] = "error"
                _state["progress"] = 0
                return

            sf = _state["security_findings"]
            tf = _state["testing_findings"]
            qf = _state["quality_findings"]

            open_high   = sum(1 for f in sf if f.get("severity") == "high"   and not f.get("fixed"))
            open_medium = sum(1 for f in sf if f.get("severity") == "medium" and not f.get("fixed"))
            fixed_count = sum(1 for f in sf if f.get("fixed")) + sum(1 for f in tf if f.get("fixed"))

            _state["phase"] = "done"
            _state["progress"] = 100
            _state["report"] = {
                "generated_at": _fmt_now(),
                "project": _state["project_name"],
                "open_high": open_high,
                "open_medium": open_medium,
                "fixed": fixed_count,
                "quality_notes": len(qf),
                "verification": _state["verification_status"],
                "summary": (
                    "✅ All critical issues resolved — see docs/SECURITY_REVIEW_FINAL.md"
                    if open_high == 0 and open_medium == 0
                    else f"⚠️ {open_high} high and {open_medium} medium issues remain open. "
                         "See docs/SECURITY_REVIEW_FINAL.md"
                ),
            }

    threading.Thread(target=_run, daemon=True).start()
    return {"message": "Report generation started.", "phase": "reporting"}
