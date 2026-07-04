"""
SCADA/ICS Engine — delegated to Rust (fingerprint_engine scada_ics).
Python only invokes the binary and returns result; no scan logic here.
"""
from __future__ import annotations
from typing import Any
from src.engines._rust_runner import run_rust_engine

def run_scada_ics(target: str, scope: dict[str, Any] | None = None) -> dict[str, Any]:
    """Run SCADA/ICS engine via Rust. Returns { status, findings, message }."""
    return run_rust_engine("scada_ics", target, timeout=90)
