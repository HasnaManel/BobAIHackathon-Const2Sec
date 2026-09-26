"""Tests for app.bob_runner — all Bob calls are mocked.

These tests verify:
  - Successful execution returns BobResult(success=True, ...)
  - Missing BOB_API_KEY returns success=False without calling subprocess
  - FileNotFoundError (bob not on PATH) returns success=False
  - Timeout returns success=False with a clear message
  - Non-zero exit code returns success=False
  - Auth failure detection from stderr text
  - UTF-8 bytes output decoded correctly (no CP1252 UnicodeDecodeError)
  - Non-ASCII / invalid bytes replaced rather than raising
  - None stdout/stderr handled safely (no AttributeError)
"""

from __future__ import annotations

import subprocess
from unittest.mock import MagicMock, patch

import pytest

from app.bob_runner import BobResult, run_bob


# ---------------------------------------------------------------------------
# Helper: build a CompletedProcess-like mock
# ---------------------------------------------------------------------------

def _completed(
    returncode: int = 0,
    stdout: bytes | str = b"done",
    stderr: bytes | str = b"",
) -> MagicMock:
    """Return a mock CompletedProcess.

    stdout/stderr default to bytes to match text=False subprocess behaviour.
    Pass str values where the test specifically exercises the str-passthrough
    path of _decode().
    """
    m = MagicMock(spec=subprocess.CompletedProcess)
    m.returncode = returncode
    m.stdout = stdout
    m.stderr = stderr
    return m


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

class TestBobRunnerSuccess:
    def test_returns_success_true_on_zero_exit(self, monkeypatch):
        monkeypatch.setenv("BOB_API_KEY", "test-key")
        with patch("subprocess.run", return_value=_completed(0, b"Analysis done", b"")) as mock_run:
            result = run_bob("test prompt")

        assert result.success is True
        assert result.returncode == 0
        assert result.stdout == "Analysis done"
        assert result.error == ""

    def test_calls_bob_run_with_correct_args(self, monkeypatch):
        from app.bob_runner import _BOB_EXECUTABLE
        monkeypatch.setenv("BOB_API_KEY", "test-key")
        with patch("subprocess.run", return_value=_completed()) as mock_run:
            run_bob("my prompt")

        args = mock_run.call_args[0][0]
        # On Windows the wrapper is "bob.cmd"; on other platforms it is "bob".
        # --trust is passed so Bob doesn't prompt for confirmation in CI/batch mode.
        assert args == [_BOB_EXECUTABLE, "run", "--trust", "my prompt"]

    def test_shell_false(self, monkeypatch):
        """shell=False must always be used — never allow shell injection."""
        monkeypatch.setenv("BOB_API_KEY", "test-key")
        with patch("subprocess.run", return_value=_completed()) as mock_run:
            run_bob("prompt")

        kwargs = mock_run.call_args[1]
        assert kwargs.get("shell") is False

    def test_api_key_in_env_not_in_args(self, monkeypatch):
        monkeypatch.setenv("BOB_API_KEY", "super-secret")
        with patch("subprocess.run", return_value=_completed()) as mock_run:
            run_bob("prompt")

        kwargs = mock_run.call_args[1]
        env = kwargs.get("env", {})
        assert env.get("BOB_API_KEY") == "super-secret"
        # Key must NOT appear in positional args
        args = mock_run.call_args[0][0]
        assert "super-secret" not in " ".join(args)


class TestBobRunnerMissingApiKey:
    def test_missing_key_returns_failure_without_subprocess(self, monkeypatch):
        monkeypatch.delenv("BOB_API_KEY", raising=False)
        with patch("subprocess.run") as mock_run:
            result = run_bob("prompt")

        assert result.success is False
        assert "BOB_API_KEY" in result.error
        mock_run.assert_not_called()

    def test_empty_key_returns_failure(self, monkeypatch):
        monkeypatch.setenv("BOB_API_KEY", "   ")
        with patch("subprocess.run") as mock_run:
            result = run_bob("prompt")

        assert result.success is False
        mock_run.assert_not_called()


class TestBobRunnerExecutableNotFound:
    def test_file_not_found_returns_failure(self, monkeypatch):
        monkeypatch.setenv("BOB_API_KEY", "test-key")
        with patch("subprocess.run", side_effect=FileNotFoundError):
            result = run_bob("prompt")

        assert result.success is False
        assert "not found" in result.error.lower() or "path" in result.error.lower()
        assert result.returncode == -1


class TestBobRunnerTimeout:
    def test_timeout_returns_failure(self, monkeypatch):
        monkeypatch.setenv("BOB_API_KEY", "test-key")
        exc = subprocess.TimeoutExpired(cmd=["bob", "run", "p"], timeout=5)
        exc.stdout = "partial"
        exc.stderr = ""
        with patch("subprocess.run", side_effect=exc):
            result = run_bob("prompt", timeout=5)

        assert result.success is False
        assert "timed out" in result.error.lower() or "timeout" in result.error.lower()
        assert result.returncode == -1


class TestBobRunnerNonZeroExit:
    def test_nonzero_exit_returns_failure(self, monkeypatch):
        monkeypatch.setenv("BOB_API_KEY", "test-key")
        with patch("subprocess.run", return_value=_completed(1, b"", b"something went wrong")):
            result = run_bob("prompt")

        assert result.success is False
        assert result.returncode == 1
        assert "1" in result.error

    def test_auth_failure_detected(self, monkeypatch):
        monkeypatch.setenv("BOB_API_KEY", "bad-key")
        with patch("subprocess.run", return_value=_completed(1, b"", b"401 Unauthorized")):
            result = run_bob("prompt")

        assert result.success is False
        assert "authentication" in result.error.lower() or "401" in result.error.lower()
        # Must never expose the key value
        assert "bad-key" not in result.error


class TestBobResultNeverExposesApiKey:
    def test_api_key_not_in_result(self, monkeypatch):
        monkeypatch.setenv("BOB_API_KEY", "very-secret-key-xyz")
        with patch("subprocess.run", return_value=_completed(1, b"out", b"err")):
            result = run_bob("prompt")

        combined = result.stdout + result.stderr + result.error
        assert "very-secret-key-xyz" not in combined


# ---------------------------------------------------------------------------
# New: encoding and None-safety tests
# ---------------------------------------------------------------------------

class TestBobRunnerEncoding:
    def test_utf8_bytes_decoded_correctly(self, monkeypatch):
        """UTF-8 multi-byte output must not raise UnicodeDecodeError."""
        monkeypatch.setenv("BOB_API_KEY", "test-key")
        utf8_output = "Analysis: ✓ résumé — 日本語".encode("utf-8")
        with patch("subprocess.run", return_value=_completed(0, utf8_output, b"")):
            result = run_bob("prompt")

        assert result.success is True
        assert "✓" in result.stdout
        assert "résumé" in result.stdout

    def test_invalid_bytes_replaced_not_raised(self, monkeypatch):
        """Bytes that are invalid UTF-8 (e.g. Windows CP1252 0x90) must be
        replaced with the Unicode replacement character, not raise an error."""
        monkeypatch.setenv("BOB_API_KEY", "test-key")
        bad_bytes = b"output \x90\x9f end"  # 0x90/0x9F invalid in UTF-8
        with patch("subprocess.run", return_value=_completed(0, bad_bytes, b"")):
            result = run_bob("prompt")  # must not raise UnicodeDecodeError

        assert result.success is True
        assert isinstance(result.stdout, str)
        # Replacement char \ufffd must appear where bad bytes were
        assert "\ufffd" in result.stdout

    def test_str_passthrough_in_decode(self):
        """_decode() with a str input returns it unchanged."""
        from app.bob_runner import _decode
        assert _decode("hello") == "hello"

    def test_none_passthrough_in_decode(self):
        """_decode() with None returns empty string."""
        from app.bob_runner import _decode
        assert _decode(None) == ""

    def test_timeout_with_none_stdout(self, monkeypatch):
        """TimeoutExpired where stdout/stderr are None must not raise."""
        monkeypatch.setenv("BOB_API_KEY", "test-key")
        exc = subprocess.TimeoutExpired(cmd=["bob.cmd", "run", "p"], timeout=5)
        exc.stdout = None
        exc.stderr = None
        with patch("subprocess.run", side_effect=exc):
            result = run_bob("prompt", timeout=5)

        assert result.success is False
        assert result.stdout == ""
        assert result.stderr == ""

    def test_timeout_with_bytes_stdout(self, monkeypatch):
        """TimeoutExpired where stdout/stderr are bytes must decode safely."""
        monkeypatch.setenv("BOB_API_KEY", "test-key")
        exc = subprocess.TimeoutExpired(cmd=["bob.cmd", "run", "p"], timeout=5)
        exc.stdout = "partial output".encode("utf-8")
        exc.stderr = b""
        with patch("subprocess.run", side_effect=exc):
            result = run_bob("prompt", timeout=5)

        assert result.success is False
        assert result.stdout == "partial output"


class TestGateTestNoneStdout:
    """Verify /gate/test doesn't AttributeError when stdout is None."""

    def test_none_stdout_treated_as_empty(self, monkeypatch):
        import time
        from app.bob_runner import BobResult
        from app import dashboard

        monkeypatch.setenv("BOB_API_KEY", "test-key")
        none_result = BobResult(success=True, stdout=None, stderr="", returncode=0)

        original_state = dashboard._state.copy()
        try:
            from fastapi.testclient import TestClient
            from app.main import app
            with TestClient(app, raise_server_exceptions=True) as c:
                with patch("app.dashboard.run_bob", return_value=none_result):
                    resp = c.post("/gate/test")
                assert resp.status_code == 202
                # Wait for background thread (mock returns instantly).
                deadline = time.monotonic() + 5.0
                while time.monotonic() < deadline:
                    s = c.get("/gate/status").json()
                    if s["phase"] != "testing":
                        break
                    time.sleep(0.05)
                assert s["verification_status"] == "passed"
        finally:
            dashboard._state.update(original_state)
