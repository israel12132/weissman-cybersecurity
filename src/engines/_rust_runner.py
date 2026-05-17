"""
Run SOC engine via Rust fingerprint_engine binary. Returns same dict shape: status, findings, message.
Used by all 5 engines so attack/scan logic lives in Rust only.
"""
from __future__ import annotations

import json
import logging
import subprocess
import time
from pathlib import Path

logger = logging.getLogger(__name__)

# Maximum number of times to retry a transient engine failure.
_DEFAULT_MAX_RETRIES = 2
# Seconds to wait between retries (doubles after each attempt).
_RETRY_BACKOFF_BASE = 0.5


def _binary_path() -> Path | None:
    base = Path(__file__).resolve().parent.parent.parent / "fingerprint_engine"
    for name in ["target/release/fingerprint_engine", "target/debug/fingerprint_engine"]:
        p = base / name
        if p.exists():
            return p
    return None


def _is_transient_failure(returncode: int, stderr: str) -> bool:
    """Return True for exit codes / stderr patterns that warrant a retry."""
    transient_patterns = ("connection refused", "timeout", "temporarily unavailable")
    stderr_lower = (stderr or "").lower()
    return returncode != 0 and any(p in stderr_lower for p in transient_patterns)


def run_rust_engine(
    engine_id: str,
    target: str,
    timeout: int = 120,
    max_retries: int = _DEFAULT_MAX_RETRIES,
) -> dict:
    """
    Invoke fingerprint_engine <engine_id> <target>; parse JSON from stdout.
    Returns {"status": "ok"|"error", "findings": [...], "message": "..."}.

    Parameters
    ----------
    engine_id:
        Name of the engine to run (passed as the first CLI argument).
    target:
        Scan target (URL, hostname, IP, …). Must be non-empty.
    timeout:
        Hard timeout in seconds before the subprocess is killed.
    max_retries:
        Number of automatic retries on transient failures.
    """
    target = (target or "").strip()
    if not target:
        return {"status": "error", "findings": [], "message": "target required"}

    engine_id = (engine_id or "").strip()
    if not engine_id:
        return {"status": "error", "findings": [], "message": "engine_id required"}

    bin_path = _binary_path()
    if not bin_path:
        logger.warning(
            "fingerprint_engine binary missing; build with: "
            "cd fingerprint_engine && cargo build --release"
        )
        return {"status": "error", "findings": [], "message": "Rust engine binary not found"}

    cwd = str(bin_path.parent.parent)
    last_error = "unknown error"

    for attempt in range(max_retries + 1):
        if attempt > 0:
            wait = _RETRY_BACKOFF_BASE * (2 ** (attempt - 1))
            logger.debug(
                "Rust engine %s: retry %d/%d after %.1fs (last error: %s)",
                engine_id, attempt, max_retries, wait, last_error,
            )
            time.sleep(wait)

        try:
            proc = subprocess.run(
                [str(bin_path), engine_id, target],
                capture_output=True,
                text=True,
                timeout=timeout,
                cwd=cwd,
            )
            stdout = (proc.stdout or "").strip()
            stderr = (proc.stderr or "").strip()

            if not stdout:
                err = stderr or f"exit {proc.returncode}"
                if attempt < max_retries and _is_transient_failure(proc.returncode, stderr):
                    last_error = err
                    continue
                return {"status": "error", "findings": [], "message": err}

            data = json.loads(stdout)
            if not isinstance(data, dict):
                return {"status": "error", "findings": [], "message": "invalid JSON from engine"}

            # Attach any stderr warnings to the message for observability.
            msg = data.get("message", "")
            if stderr:
                msg = f"{msg} [stderr: {stderr[:200]}]".strip(" [")
                msg = msg.rstrip("]")

            return {
                "status": data.get("status", "error"),
                "findings": data.get("findings", []) if isinstance(data.get("findings"), list) else [],
                "message": msg,
            }

        except subprocess.TimeoutExpired:
            last_error = f"engine timeout after {timeout}s"
            if attempt < max_retries:
                continue
            return {"status": "error", "findings": [], "message": last_error}

        except json.JSONDecodeError as exc:
            return {"status": "error", "findings": [], "message": f"JSON parse: {exc}"}

        except Exception as exc:
            logger.exception("Rust engine %s failed: %s", engine_id, exc)
            last_error = str(exc)
            if attempt < max_retries:
                continue
            return {"status": "error", "findings": [], "message": last_error}

    return {"status": "error", "findings": [], "message": last_error}
