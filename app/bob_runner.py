"""bob_runner.py — Safe wrapper around the Bob Shell CLI.

Executes ``bob run "<prompt>"`` as a subprocess.  Only four hard-coded
prompts may be used; no user-supplied text ever reaches the shell.

Environment:
    BOB_API_KEY   Required.  Passed to the Bob process via its environment.
                  Never returned to the caller or logged.

Raises:
    RuntimeError  When BOB_API_KEY is missing, bob is not found, or the
                  subprocess exits with a non-zero code.
    TimeoutError  When the subprocess does not complete within *timeout*
                  seconds.
"""

from __future__ import annotations

import os
import subprocess
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Final

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

# On Windows, Python subprocess cannot find npm-installed CLI wrappers by the
# bare name "bob" because they are installed as "bob.cmd" / "bob.ps1".
# Use "bob.cmd" on Windows so shell=False still works; other platforms keep "bob".
_BOB_EXECUTABLE: Final[str] = "bob.cmd" if sys.platform == "win32" else "bob"
_DEFAULT_TIMEOUT: Final[int] = 600  # 10 minutes — long-running analysis

# The repository root is the directory that contains this file's parent (app/).
REPO_ROOT: Final[Path] = Path(__file__).parent.parent.resolve()


# ---------------------------------------------------------------------------
# Result type
# ---------------------------------------------------------------------------

@dataclass
class BobResult:
    """Outcome of a single Bob run."""

    success: bool
    stdout: str
    stderr: str
    returncode: int
    error: str = ""  # human-readable summary when success is False


# ---------------------------------------------------------------------------
# Core runner
# ---------------------------------------------------------------------------

def _decode(raw: bytes | str | None) -> str:
    """Decode subprocess output bytes as UTF-8, replacing undecodable bytes.

    Handles three cases produced by subprocess:
      - bytes  — decode with UTF-8, replacing any bad bytes rather than raising.
      - str    — returned as-is (already decoded by text=True, should not happen
                 with our binary capture, but defensive).
      - None   — subprocess produced no output; return empty string.
    """
    if raw is None:
        return ""
    if isinstance(raw, bytes):
        return raw.decode("utf-8", errors="replace")
    return raw  # already a str


def run_bob(prompt: str, *, timeout: int = _DEFAULT_TIMEOUT) -> BobResult:
    """Execute ``bob run "<prompt>"`` and return a structured result.

    Args:
        prompt:   The exact prompt string to send.  Must be one of the four
                  values defined in _ALLOWED_PROMPTS (enforced by the callers
                  in dashboard.py — this function itself does not whitelist).
        timeout:  Maximum wall-clock seconds to wait.  Defaults to 600 s.

    Returns:
        BobResult with success=True and captured output on success.
        BobResult with success=False and a safe error message on failure.
    """
    api_key = os.environ.get("BOB_API_KEY", "").strip()
    if not api_key:
        return BobResult(
            success=False,
            stdout="",
            stderr="",
            returncode=-1,
            error="BOB_API_KEY environment variable is not set.",
        )

    # Build environment: inherit current env but ensure BOB_API_KEY is set.
    env = {**os.environ, "BOB_API_KEY": api_key}

    cmd = [_BOB_EXECUTABLE, "run", "--trust", prompt]

    try:
        # Capture raw bytes so we control the decode step.  Using text=True
        # lets Python pick the platform default encoding (CP1252 on Windows),
        # which fails on UTF-8 / Unicode output from Node.js / Bob.
        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=False,   # capture bytes; we decode below with UTF-8
            timeout=timeout,
            cwd=str(REPO_ROOT),
            env=env,
            shell=False,  # explicit — never allow shell injection
        )
    except FileNotFoundError:
        return BobResult(
            success=False,
            stdout="",
            stderr="",
            returncode=-1,
            error="Bob executable not found.  Ensure 'bob' is on PATH.",
        )
    except subprocess.TimeoutExpired as exc:
        # exc.stdout / exc.stderr may be bytes or None when text=False.
        return BobResult(
            success=False,
            stdout=_decode(exc.stdout),
            stderr=_decode(exc.stderr),
            returncode=-1,
            error=f"Bob timed out after {timeout} seconds.",
        )

    stdout = _decode(proc.stdout)
    stderr = _decode(proc.stderr)

    success = proc.returncode == 0
    error = ""
    if not success:
        # Detect auth failure heuristically — never expose the key.
        lower_err = stderr.lower()
        if "unauthorized" in lower_err or "authentication" in lower_err or "401" in lower_err:
            error = "Bob authentication failed.  Check BOB_API_KEY."
        else:
            error = f"Bob exited with code {proc.returncode}."

    return BobResult(
        success=success,
        stdout=stdout,
        stderr=stderr,
        returncode=proc.returncode,
        error=error,
    )
