"""Tests for /gate/* endpoints — Bob is fully mocked.

Covers:
  - POST /gate/analyze  — success path
  - POST /gate/analyze  — Bob failure propagated as 502
  - POST /gate/test     — pass/fail detection from Bob stdout
  - POST /gate/fix      — concurrent protection (409)
  - GET  /gate/status   — BOB_API_KEY not in response; subagent_findings present
  - GET  /gate/report   — success path
  - No auth required    — /gate/* endpoints are public (local hackathon demo)
  - /gate/status remains public
  - subagent_findings field population, agent names, severity, file/line
"""

from __future__ import annotations

import json
import threading
import time
from pathlib import Path
from unittest.mock import patch

import pytest
from fastapi.testclient import TestClient

from app.bob_runner import BobResult
from app.main import app


# ---------------------------------------------------------------------------
# Helper: wait for async background thread to finish by polling /gate/status
# ---------------------------------------------------------------------------

def _wait_for_phase(client, running_phase: str, timeout: float = 5.0) -> dict:
    """Poll /gate/status until the phase is no longer *running_phase*.

    Returns the final status dict.  The background thread in the test uses a
    mock that returns instantly, so this typically resolves in < 100 ms.
    """
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        s = client.get("/gate/status").json()
        if s["phase"] != running_phase:
            return s
        time.sleep(0.05)
    return client.get("/gate/status").json()

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

_SUCCESS = BobResult(success=True, stdout="Bob output here", stderr="", returncode=0)
_FAILURE = BobResult(success=False, stdout="", stderr="", returncode=1, error="Bob exited with code 1.")
_AUTH_FAILURE = BobResult(success=False, stdout="", stderr="401 Unauthorized", returncode=1, error="Bob authentication failed.  Check BOB_API_KEY.")


@pytest.fixture()
def gate_client(monkeypatch):
    """TestClient with a fresh gate state; no real Bob calls."""
    import app.dashboard as dash
    dash._state = dict(dash._INITIAL_STATE)
    dash._fix_running = False

    monkeypatch.setenv("BOB_API_KEY", "mock-key")
    with TestClient(app, raise_server_exceptions=False) as c:
        yield c


# ---------------------------------------------------------------------------
# Sample docs fixtures — written to REPO_ROOT/docs/ during tests
# ---------------------------------------------------------------------------

_SAMPLE_MD = """\
# Security Review

## Summary
Two findings.

### FIND-001: Missing ownership check
**ID:** FIND-001
**Severity:** high
**Title:** Missing ownership check on DELETE /products/{id}
**File:** app/products.py
**Line:** 71
**Detail:** Any authenticated user can delete any product.

### FIND-002: Hardcoded signing key
**ID:** FIND-002
**Severity:** high
**Title:** Hardcoded JWT signing key fallback
**File:** app/auth.py
**Line:** 28
**Detail:** APP_SIGNING_KEY defaults to 'changeme'.
"""

_SAMPLE_SUBAGENT_JSON = json.dumps([
    {
        "agent": "Authentication & Authorization Agent",
        "id": "AUTH-001",
        "severity": "high",
        "title": "Missing ownership check",
        "file": "app/products.py",
        "line": 71,
        "detail": "Any authenticated user can delete any product.",
    },
    {
        "agent": "Secrets & Configuration Agent",
        "id": "SEC-001",
        "severity": "high",
        "title": "Hardcoded JWT signing key",
        "file": "app/auth.py",
        "line": 28,
        "detail": "APP_SIGNING_KEY defaults to 'changeme'.",
    },
    {
        "agent": "Input Validation Agent",
        "id": "VAL-001",
        "severity": "medium",
        "title": "No input length limit on username",
        "file": "app/auth.py",
        "line": 95,
        "detail": "Username field accepts arbitrarily long strings.",
    },
])


@pytest.fixture()
def with_docs(tmp_path, monkeypatch):
    """Write sample docs files and patch REPO_ROOT so dashboard reads them."""
    docs = tmp_path / "docs"
    docs.mkdir()
    (docs / "SECURITY_REVIEW_BEFORE_FIX.md").write_text(_SAMPLE_MD, encoding="utf-8")
    (docs / "SUBAGENT_FINDINGS.json").write_text(_SAMPLE_SUBAGENT_JSON, encoding="utf-8")

    import app.dashboard as dash
    monkeypatch.setattr(dash, "_load_consolidated_findings",
                        lambda: _patched_load_consolidated(tmp_path))
    monkeypatch.setattr(dash, "_load_subagent_findings",
                        lambda: _patched_load_subagent(tmp_path))
    yield tmp_path


def _patched_load_consolidated(root: Path) -> list[dict]:
    """Re-implement _load_consolidated_findings pointing at a temp root."""
    import re

    def _mf(sec: str, lbl: str) -> str:
        esc = re.escape(lbl)
        m = re.search(r'\*\*' + esc + r':?\*\*:?\s*([^\n]+)', sec, re.IGNORECASE)
        return m.group(1).strip() if m else ""

    path = root / "docs" / "SECURITY_REVIEW_BEFORE_FIX.md"
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except Exception:
        return []
    findings: list[dict] = []
    sections = re.split(r'\n(?=###\s)', text)
    for sec in sections:
        first_line = sec.strip().splitlines()[0] if sec.strip() else ""
        if not first_line.startswith("###"):
            continue
        finding_id = _mf(sec, "ID") or _mf(sec, "id")
        if not finding_id:
            m = re.match(r'###\s+([\w-]+)', first_line)
            finding_id = m.group(1) if m else ""
        severity = (_mf(sec, "Severity") or _mf(sec, "severity") or "info").lower().strip()
        title = _mf(sec, "Title") or _mf(sec, "title")
        if not title:
            m = re.match(r'###\s+[\w-]+[:\s]+(.*)', first_line)
            title = m.group(1).strip() if m else first_line.lstrip("# ").strip()
        file_val = _mf(sec, "File") or _mf(sec, "file") or _mf(sec, "Affected File")
        line_val = _mf(sec, "Line") or _mf(sec, "line")
        detail = _mf(sec, "Detail") or _mf(sec, "detail") or _mf(sec, "Explanation")
        line_int: int | None = None
        if line_val:
            m = re.search(r'\d+', line_val)
            if m:
                line_int = int(m.group())
        if not finding_id and not title:
            continue
        findings.append({
            "id": finding_id, "severity": severity,
            "title": title, "file": file_val, "line": line_int,
            "detail": detail, "fixed": False,
        })
    return findings


def _patched_load_subagent(root: Path) -> list[dict]:
    """Re-implement _load_subagent_findings pointing at a temp root."""
    path = root / "docs" / "SUBAGENT_FINDINGS.json"
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
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
                "line":     item.get("line"),
                "detail":   str(item.get("detail", "")),
            })
        return findings
    except Exception:
        return []


# ---------------------------------------------------------------------------
# No auth required — /gate/* endpoints are public (hackathon demo)
# ---------------------------------------------------------------------------

class TestGateNoAuthRequired:
    """/gate/* endpoints must be accessible without any authentication."""

    def test_status_accessible_without_auth(self, gate_client):
        resp = gate_client.get("/gate/status")
        assert resp.status_code == 200

    def test_analyze_accessible_without_auth(self, gate_client, with_docs):
        with patch("app.dashboard.run_bob", return_value=_SUCCESS):
            resp = gate_client.post("/gate/analyze")
        assert resp.status_code == 202

    def test_fix_accessible_without_auth(self, gate_client):
        import app.dashboard as dash
        dash._state["security_findings"] = []
        resp = gate_client.post("/gate/fix")
        assert resp.status_code == 202

    def test_test_accessible_without_auth(self, gate_client):
        ok = BobResult(success=True, stdout="5 passed", stderr="", returncode=0)
        with patch("app.dashboard.run_bob", return_value=ok):
            resp = gate_client.post("/gate/test")
        assert resp.status_code == 202

    def test_report_accessible_without_auth(self, gate_client):
        with patch("app.dashboard.run_bob", return_value=_SUCCESS):
            resp = gate_client.get("/gate/report")
        assert resp.status_code == 202


# ---------------------------------------------------------------------------
# /gate/status — includes subagent_findings
# ---------------------------------------------------------------------------

class TestGateStatus:
    def test_status_returns_expected_fields(self, gate_client):
        resp = gate_client.get("/gate/status")
        assert resp.status_code == 200
        data = resp.json()
        assert "phase" in data
        assert "security_findings" in data
        assert "subagent_findings" in data
        assert "verification_status" in data
        assert "report" in data

    def test_subagent_findings_initially_empty(self, gate_client):
        resp = gate_client.get("/gate/status")
        assert resp.status_code == 200
        assert resp.json()["subagent_findings"] == []

    def test_api_key_not_in_status_response(self, gate_client, monkeypatch):
        monkeypatch.setenv("BOB_API_KEY", "should-never-appear")
        resp = gate_client.get("/gate/status")
        assert "should-never-appear" not in resp.text


# ---------------------------------------------------------------------------
# POST /gate/analyze — subagent_findings and security_findings population
# ---------------------------------------------------------------------------

class TestGateAnalyze:
    def test_analyze_success(self, gate_client, with_docs):
        with patch("app.dashboard.run_bob", return_value=_SUCCESS):
            resp = gate_client.post("/gate/analyze")
        assert resp.status_code == 202
        data = resp.json()
        assert "message" in data

    def test_analyze_populates_both_finding_lists(self, gate_client, with_docs):
        """Analyze must populate both security_findings and subagent_findings."""
        with patch("app.dashboard.run_bob", return_value=_SUCCESS):
            gate_client.post("/gate/analyze")
        # Wait for the background thread to complete (mock returns instantly).
        status = _wait_for_phase(gate_client, "analyzing")
        assert status["phase"] == "done"
        assert status["progress"] == 100
        # Consolidated findings from markdown
        assert len(status["security_findings"]) > 0
        # Subagent findings from JSON
        assert len(status["subagent_findings"]) > 0

    def test_consolidated_findings_have_required_fields(self, gate_client, with_docs):
        """Each consolidated finding must have id, severity, title, fixed."""
        with patch("app.dashboard.run_bob", return_value=_SUCCESS):
            gate_client.post("/gate/analyze")
        _wait_for_phase(gate_client, "analyzing")
        findings = gate_client.get("/gate/status").json()["security_findings"]
        for f in findings:
            assert "id" in f
            assert "severity" in f
            assert "title" in f
            assert "fixed" in f

    def test_subagent_findings_have_required_fields(self, gate_client, with_docs):
        """Each subagent finding must have agent, severity, title."""
        with patch("app.dashboard.run_bob", return_value=_SUCCESS):
            gate_client.post("/gate/analyze")
        _wait_for_phase(gate_client, "analyzing")
        subagent = gate_client.get("/gate/status").json()["subagent_findings"]
        for f in subagent:
            assert "agent" in f
            assert "severity" in f
            assert "title" in f

    def test_subagent_findings_multiple_agents(self, gate_client, with_docs):
        """Multiple distinct agent names must appear in subagent_findings."""
        with patch("app.dashboard.run_bob", return_value=_SUCCESS):
            gate_client.post("/gate/analyze")
        _wait_for_phase(gate_client, "analyzing")
        subagent = gate_client.get("/gate/status").json()["subagent_findings"]
        agents = {f["agent"] for f in subagent}
        assert len(agents) >= 2, f"Expected multiple agents, got: {agents}"

    def test_subagent_agent_names_preserved(self, gate_client, with_docs):
        """Exact agent name strings from the JSON must appear in the response."""
        with patch("app.dashboard.run_bob", return_value=_SUCCESS):
            gate_client.post("/gate/analyze")
        _wait_for_phase(gate_client, "analyzing")
        subagent = gate_client.get("/gate/status").json()["subagent_findings"]
        agents = {f["agent"] for f in subagent}
        assert "Authentication & Authorization Agent" in agents
        assert "Secrets & Configuration Agent" in agents

    def test_subagent_severity_preserved(self, gate_client, with_docs):
        """Severity values from the JSON must be present in the response."""
        with patch("app.dashboard.run_bob", return_value=_SUCCESS):
            gate_client.post("/gate/analyze")
        _wait_for_phase(gate_client, "analyzing")
        subagent = gate_client.get("/gate/status").json()["subagent_findings"]
        severities = {f["severity"] for f in subagent}
        assert "high" in severities

    def test_subagent_file_and_line_preserved(self, gate_client, with_docs):
        """File and line information must be carried through to the response."""
        with patch("app.dashboard.run_bob", return_value=_SUCCESS):
            gate_client.post("/gate/analyze")
        _wait_for_phase(gate_client, "analyzing")
        subagent = gate_client.get("/gate/status").json()["subagent_findings"]
        auth_findings = [f for f in subagent if f.get("agent") == "Authentication & Authorization Agent"]
        assert len(auth_findings) > 0
        f = auth_findings[0]
        assert f["file"] == "app/products.py"
        assert f["line"] == 71

    def test_no_fake_hardcoded_data(self, gate_client, with_docs):
        """Finding titles must come from the sample docs, not hard-coded strings."""
        with patch("app.dashboard.run_bob", return_value=_SUCCESS):
            gate_client.post("/gate/analyze")
        _wait_for_phase(gate_client, "analyzing")
        status = gate_client.get("/gate/status").json()
        titles = {f["title"] for f in status["security_findings"]}
        # Old placeholder must not appear; real title from sample docs must
        assert "Security analysis complete — see docs/SECURITY_REVIEW_BEFORE_FIX.md" not in titles
        assert "Missing ownership check on DELETE /products/{id}" in titles

    def test_subagent_findings_not_merged_with_consolidated(self, gate_client, with_docs):
        """The two lists must be separate — no duplicate entries across them."""
        with patch("app.dashboard.run_bob", return_value=_SUCCESS):
            gate_client.post("/gate/analyze")
        _wait_for_phase(gate_client, "analyzing")
        status = gate_client.get("/gate/status").json()
        consolidated_ids = {f.get("id") for f in status["security_findings"]}
        subagent_ids = {f.get("id") for f in status["subagent_findings"]}
        # They should use different ID namespaces (FIND-* vs AUTH-*/SEC-*/VAL-*)
        overlap = consolidated_ids & subagent_ids
        assert len(overlap) == 0, f"Unexpected overlap between lists: {overlap}"

    def test_analyze_bob_failure_sets_error_phase(self, gate_client):
        """When Bob fails and no output files exist, phase becomes 'error'."""
        # Patch the loaders to return empty (simulate fresh repo with no prior docs).
        with patch("app.dashboard._load_consolidated_findings", return_value=[]), \
             patch("app.dashboard._load_subagent_findings", return_value=[]), \
             patch("app.dashboard.run_bob", return_value=_FAILURE):
            resp = gate_client.post("/gate/analyze")
        assert resp.status_code == 202
        status = _wait_for_phase(gate_client, "analyzing")
        assert status["phase"] == "error"

    def test_analyze_auth_failure_sets_error_phase(self, gate_client, monkeypatch):
        """Auth failure with no output files sets phase to 'error'; key must not leak."""
        monkeypatch.setenv("BOB_API_KEY", "mock-key")
        # Patch the loaders to return empty (simulate fresh repo with no prior docs).
        with patch("app.dashboard._load_consolidated_findings", return_value=[]), \
             patch("app.dashboard._load_subagent_findings", return_value=[]), \
             patch("app.dashboard.run_bob", return_value=_AUTH_FAILURE):
            resp = gate_client.post("/gate/analyze")
        assert resp.status_code == 202
        assert "mock-key" not in resp.text
        status = _wait_for_phase(gate_client, "analyzing")
        assert status["phase"] == "error"

    def test_analyze_bob_prompt_is_hardcoded(self, gate_client, with_docs):
        captured = {}
        def fake_run(prompt, **kwargs):
            captured["prompt"] = prompt
            return _SUCCESS
        with patch("app.dashboard.run_bob", side_effect=fake_run):
            gate_client.post("/gate/analyze")
        assert "security" in captured["prompt"].lower()
        assert "SECURITY_REVIEW_BEFORE_FIX" in captured["prompt"]
        assert "SUBAGENT_FINDINGS.json" in captured["prompt"]


# ---------------------------------------------------------------------------
# POST /gate/test
# ---------------------------------------------------------------------------

class TestGateTest:
    def test_test_passed_when_no_failure_keyword(self, gate_client):
        ok = BobResult(success=True, stdout="5 passed in 1.2s", stderr="", returncode=0)
        with patch("app.dashboard.run_bob", return_value=ok):
            resp = gate_client.post("/gate/test")
        assert resp.status_code == 202
        status = _wait_for_phase(gate_client, "testing")
        assert status["verification_status"] == "passed"

    def test_test_failed_when_failed_keyword_present(self, gate_client):
        fail = BobResult(success=True, stdout="2 failed, 3 passed", stderr="", returncode=0)
        with patch("app.dashboard.run_bob", return_value=fail):
            resp = gate_client.post("/gate/test")
        assert resp.status_code == 202
        status = _wait_for_phase(gate_client, "testing")
        assert status["verification_status"] == "failed"

    def test_test_bob_infra_failure_marks_verification_failed(self, gate_client):
        """A Bob infra failure (returncode=-1) must set verification_status=failed."""
        infra_fail = BobResult(success=False, stdout="", stderr="", returncode=-1,
                               error="Bob executable not found.")
        with patch("app.dashboard.run_bob", return_value=infra_fail):
            resp = gate_client.post("/gate/test")
        assert resp.status_code == 202
        status = _wait_for_phase(gate_client, "testing")
        assert status["verification_status"] == "failed"

    def test_test_status_reflects_real_outcome(self, gate_client):
        import app.dashboard as dash
        dash._state["security_findings"] = [
            {"id": "X", "severity": "high", "fixed": False,
             "title": "t", "file": "f", "line": None, "detail": "d"}
        ]
        ok = BobResult(success=True, stdout="10 passed", stderr="", returncode=0)
        with patch("app.dashboard.run_bob", return_value=ok):
            gate_client.post("/gate/test")
        status = gate_client.get("/gate/status").json()
        assert status["verification_status"] == "passed"


# ---------------------------------------------------------------------------
# POST /gate/fix — subagent findings not marked fixed
# ---------------------------------------------------------------------------

class TestGateFix:
    def test_fix_no_findings_returns_message(self, gate_client):
        import app.dashboard as dash
        dash._state["security_findings"] = []
        with patch("app.dashboard.run_bob", return_value=_SUCCESS):
            resp = gate_client.post("/gate/fix")
        assert resp.status_code == 202
        assert "analysis" in resp.json()["message"].lower()

    def test_fix_success_marks_consolidated_findings_fixed(self, gate_client):
        import app.dashboard as dash
        dash._state["security_findings"] = [
            {"id": "F1", "severity": "high", "fixed": False,
             "title": "t", "file": "f", "line": None, "detail": "d"}
        ]
        with patch("app.dashboard.run_bob", return_value=_SUCCESS):
            resp = gate_client.post("/gate/fix")
        assert resp.status_code == 202
        _wait_for_phase(gate_client, "fixing")
        status = gate_client.get("/gate/status").json()
        assert status["security_findings"][0]["fixed"] is True

    def test_fix_does_not_mark_subagent_findings_fixed(self, gate_client):
        """Fix must not touch subagent_findings — they are independent observations."""
        import app.dashboard as dash
        dash._state["security_findings"] = [
            {"id": "F1", "severity": "high", "fixed": False,
             "title": "t", "file": "f", "line": None, "detail": "d"}
        ]
        dash._state["subagent_findings"] = [
            {"agent": "Auth Agent", "id": "A1", "severity": "high",
             "title": "t", "file": "f", "line": None, "detail": "d"}
        ]
        with patch("app.dashboard.run_bob", return_value=_SUCCESS):
            gate_client.post("/gate/fix")
        status = gate_client.get("/gate/status").json()
        # Subagent findings have no "fixed" field — they must remain as-is
        assert "fixed" not in status["subagent_findings"][0]

    def test_concurrent_fix_returns_409(self, gate_client):
        import app.dashboard as dash
        dash._state["security_findings"] = [
            {"id": "F1", "severity": "high", "fixed": False,
             "title": "t", "file": "f", "line": None, "detail": "d"}
        ]
        dash._fix_running = True
        try:
            resp = gate_client.post("/gate/fix")
            assert resp.status_code == 409
        finally:
            dash._fix_running = False


# ---------------------------------------------------------------------------
# GET /gate/report
# ---------------------------------------------------------------------------

class TestGateReport:
    def test_report_success(self, gate_client):
        with patch("app.dashboard.run_bob", return_value=_SUCCESS):
            resp = gate_client.get("/gate/report")
        assert resp.status_code == 202
        status = _wait_for_phase(gate_client, "reporting")
        assert status["report"] is not None
        r = status["report"]
        assert "generated_at" in r
        assert "summary" in r
        assert "SECURITY_REVIEW_FINAL" in r["summary"] or "issues" in r["summary"]

    def test_report_bob_infra_failure_sets_error_phase(self, gate_client):
        """A Bob infra failure (returncode=-1) must set phase=error."""
        infra_fail = BobResult(success=False, stdout="", stderr="", returncode=-1,
                               error="Bob executable not found.")
        with patch("app.dashboard.run_bob", return_value=infra_fail):
            resp = gate_client.get("/gate/report")
        assert resp.status_code == 202
        status = _wait_for_phase(gate_client, "reporting")
        assert status["phase"] == "error"

    def test_api_key_not_in_report_response(self, gate_client, monkeypatch):
        monkeypatch.setenv("BOB_API_KEY", "never-leak-this")
        with patch("app.dashboard.run_bob", return_value=_SUCCESS):
            resp = gate_client.get("/gate/report")
        assert "never-leak-this" not in resp.text


# ---------------------------------------------------------------------------
# _load_* unit tests — exercise parsers directly without the HTTP layer
# ---------------------------------------------------------------------------

class TestLoadHelpers:
    def test_load_subagent_findings_valid_json(self, tmp_path):
        from app.dashboard import _load_subagent_findings
        import app.dashboard as dash
        docs = tmp_path / "docs"
        docs.mkdir()
        (docs / "SUBAGENT_FINDINGS.json").write_text(_SAMPLE_SUBAGENT_JSON, encoding="utf-8")
        orig = dash.REPO_ROOT
        dash.REPO_ROOT = tmp_path
        try:
            result = _load_subagent_findings()
        finally:
            dash.REPO_ROOT = orig
        assert len(result) == 3
        agents = {f["agent"] for f in result}
        assert "Authentication & Authorization Agent" in agents
        assert "Input Validation Agent" in agents

    def test_load_subagent_findings_missing_file(self, tmp_path):
        from app.dashboard import _load_subagent_findings
        import app.dashboard as dash
        orig = dash.REPO_ROOT
        dash.REPO_ROOT = tmp_path  # no docs/ dir
        try:
            result = _load_subagent_findings()
        finally:
            dash.REPO_ROOT = orig
        assert result == []

    def test_load_subagent_findings_malformed_json(self, tmp_path):
        from app.dashboard import _load_subagent_findings
        import app.dashboard as dash
        docs = tmp_path / "docs"
        docs.mkdir()
        (docs / "SUBAGENT_FINDINGS.json").write_text("{not valid json}", encoding="utf-8")
        orig = dash.REPO_ROOT
        dash.REPO_ROOT = tmp_path
        try:
            result = _load_subagent_findings()
        finally:
            dash.REPO_ROOT = orig
        assert result == []

    def test_load_consolidated_findings_parses_markdown(self, tmp_path):
        from app.dashboard import _load_consolidated_findings
        import app.dashboard as dash
        docs = tmp_path / "docs"
        docs.mkdir()
        (docs / "SECURITY_REVIEW_BEFORE_FIX.md").write_text(_SAMPLE_MD, encoding="utf-8")
        orig = dash.REPO_ROOT
        dash.REPO_ROOT = tmp_path
        try:
            result = _load_consolidated_findings()
        finally:
            dash.REPO_ROOT = orig
        assert len(result) == 2
        ids = {f["id"] for f in result}
        assert "FIND-001" in ids
        assert "FIND-002" in ids

    def test_load_consolidated_findings_file_missing(self, tmp_path):
        from app.dashboard import _load_consolidated_findings
        import app.dashboard as dash
        orig = dash.REPO_ROOT
        dash.REPO_ROOT = tmp_path
        try:
            result = _load_consolidated_findings()
        finally:
            dash.REPO_ROOT = orig
        assert result == []

    def test_load_consolidated_severity_and_file(self, tmp_path):
        from app.dashboard import _load_consolidated_findings
        import app.dashboard as dash
        docs = tmp_path / "docs"
        docs.mkdir()
        (docs / "SECURITY_REVIEW_BEFORE_FIX.md").write_text(_SAMPLE_MD, encoding="utf-8")
        orig = dash.REPO_ROOT
        dash.REPO_ROOT = tmp_path
        try:
            result = _load_consolidated_findings()
        finally:
            dash.REPO_ROOT = orig
        f1 = next(f for f in result if f["id"] == "FIND-001")
        assert f1["severity"] == "high"
        assert f1["file"] == "app/products.py"
        assert f1["line"] == 71
        assert f1["fixed"] is False
