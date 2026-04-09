"""
Run SOC engine via Rust fingerprint_engine binary. Returns same dict shape: status, findings, message.
Used by all 5 engines so attack/scan logic lives in Rust only.
"""
from __future__ import annotations

import json
import logging
import subprocess
from pathlib import Path

logger = logging.getLogger(__name__)

def _binary_path() -> Path | None:
    base = Path(__file__).resolve().parent.parent.parent / "fingerprint_engine"
    for name in ["target/release/fingerprint_engine", "target/debug/fingerprint_engine"]:
        p = base / name
        if p.exists():
            return p
    return None


def run_rust_engine(engine_id: str, target: str, timeout: int = 120) -> dict:
    """
    Invoke fingerprint_engine <engine_id> <target>; parse JSON from stdout.
    Returns {"status": "ok"|"error", "findings": [...], "message": "..."}.
    """
    target = (target or "").strip()
    if not target:
        return {"status": "error", "findings": [], "message": "target required"}

    bin_path = _binary_path()
    if not bin_path:
        logger.warning("fingerprint_engine binary missing; build with: cd fingerprint_engine && cargo build --release")
        return {"status": "error", "findings": [], "message": "Rust engine binary not found"}

    cwd = str(bin_path.parent.parent)
    try:
        proc = subprocess.run(
            [str(bin_path), engine_id, target],
            capture_output=True,
            text=True,
            timeout=timeout,
            cwd=cwd,
        )
        out = (proc.stdout or "").strip()
        if not out:
            err = (proc.stderr or "").strip() or f"exit {proc.returncode}"
            return {"status": "error", "findings": [], "message": err}
        data = json.loads(out)
        if not isinstance(data, dict):
            return {"status": "error", "findings": [], "message": "invalid JSON from engine"}
        return {
            "status": data.get("status", "error"),
            "findings": data.get("findings", []) if isinstance(data.get("findings"), list) else [],
            "message": data.get("message", ""),
        }
    except subprocess.TimeoutExpired:
        return {"status": "error", "findings": [], "message": "engine timeout"}
    except json.JSONDecodeError as e:
        return {"status": "error", "findings": [], "message": f"JSON parse: {e}"}
    except Exception as e:
        logger.exception("Rust engine %s failed: %s", engine_id, e)
        return {"status": "error", "findings": [], "message": str(e)}
