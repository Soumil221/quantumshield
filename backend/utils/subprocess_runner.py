# utils/subprocess_runner.py
#
# Centralised subprocess execution layer for Quantum Shield.
#
# All external tool calls (subfinder, nmap, …) go through this module so that:
#   - Timeout handling is uniform
#   - Missing-binary errors surface with actionable messages
#   - Logging is consistent across every tool
#   - The rest of the codebase never imports subprocess directly

import logging
import shutil
import subprocess
from dataclasses import dataclass, field

logger = logging.getLogger(__name__)

# Default wall-clock limit for any single subprocess call.
DEFAULT_TIMEOUT: int = 120  # seconds


@dataclass
class SubprocessResult:
    """
    Structured return type for every run_command() call.

    Using a dataclass (rather than a bare tuple) makes call-sites
    self-documenting and easy to pattern-match against.
    """

    stdout: str
    stderr: str
    returncode: int
    timed_out: bool = False
    tool_missing: bool = False
    error_message: str = ""
    args: list[str] = field(default_factory=list)

    # ------------------------------------------------------------------ #
    # Convenience helpers                                                  #
    # ------------------------------------------------------------------ #

    @property
    def success(self) -> bool:
        """True when the process exited cleanly with no structural errors."""
        return (
            not self.timed_out
            and not self.tool_missing
            and not self.error_message
            and self.returncode == 0
        )

    @property
    def stdout_lines(self) -> list[str]:
        """Non-empty, stripped lines from stdout — ready to iterate."""
        return [ln.strip() for ln in self.stdout.splitlines() if ln.strip()]


def is_tool_installed(binary: str) -> bool:
    """
    Return True if *binary* is reachable on PATH.

    Uses shutil.which() which respects the full PATH resolution rules,
    including venv bin directories.
    """
    return shutil.which(binary) is not None


def run_command(
    args: list[str],
    *,
    timeout: int = DEFAULT_TIMEOUT,
    capture_stderr: bool = True,
) -> SubprocessResult:
    """
    Execute an external command and return a structured result.

    Args:
        args:           Full command as a list, e.g. ['nmap', '-p', '80', '1.2.3.4'].
        timeout:        Wall-clock seconds before the process is killed.
        capture_stderr: When True, stderr is captured into the result object.
                        Set False to let it flow to the terminal (useful in debug).

    Returns:
        SubprocessResult — always returns, never raises.  Callers inspect
        .success / .timed_out / .tool_missing to decide how to proceed.

    Design note:
        We deliberately swallow all exceptions here so that a single broken
        tool call cannot crash the entire scan pipeline.  Each caller is
        responsible for deciding whether a failure is fatal or skippable.
    """
    binary = args[0] if args else ""

    # ── Pre-flight: verify binary exists before forking ──────────────────── #
    if binary and not is_tool_installed(binary):
        msg = (
            f"Required tool '{binary}' was not found on PATH. "
            f"Install it and ensure it is accessible to this process."
        )
        logger.error(msg)
        return SubprocessResult(
            stdout="",
            stderr="",
            returncode=-1,
            tool_missing=True,
            error_message=msg,
            args=args,
        )

    logger.debug("Running command: %s  (timeout=%ds)", " ".join(args), timeout)

    try:
        proc = subprocess.run(
            args,
            capture_output=True,
            text=True,
            timeout=timeout,
        )

        if proc.returncode != 0:
            # Log as warning, not error — nmap returns non-zero for valid scans
            # on hosts that respond unexpectedly; callers decide significance.
            logger.warning(
                "Command exited with code %d: %s",
                proc.returncode,
                " ".join(args),
            )
            if proc.stderr:
                logger.warning("stderr: %s", proc.stderr.strip())

        return SubprocessResult(
            stdout=proc.stdout,
            stderr=proc.stderr if capture_stderr else "",
            returncode=proc.returncode,
            args=args,
        )

    except subprocess.TimeoutExpired:
        msg = (
            f"Command timed out after {timeout}s: {' '.join(args)}"
        )
        logger.error(msg)
        return SubprocessResult(
            stdout="",
            stderr="",
            returncode=-1,
            timed_out=True,
            error_message=msg,
            args=args,
        )

    except FileNotFoundError:
        # Race condition: binary disappeared between shutil.which() and fork.
        msg = f"Binary '{binary}' disappeared between PATH check and execution."
        logger.error(msg)
        return SubprocessResult(
            stdout="",
            stderr="",
            returncode=-1,
            tool_missing=True,
            error_message=msg,
            args=args,
        )

    except Exception as exc:  # noqa: BLE001
        msg = f"Unexpected error running '{' '.join(args)}': {exc}"
        logger.exception(msg)
        return SubprocessResult(
            stdout="",
            stderr="",
            returncode=-1,
            error_message=msg,
            args=args,
        )