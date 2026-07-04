"""
PQC Scanner Engine — delegated to Rust (fingerprint_engine pqc_scanner).
Python only invokes the binary and returns result; no scan logic here.
"""
from __future__ import annotations
from typing import Any
from src.engines._rust_runner import run_rust_engine

def run_pqc_scanner(target: str, scope: dict[str, Any] | None = None) -> dict[str, Any]:
    """Run PQC Scanner engine via Rust. Returns { status, findings, message }."""
    return run_rust_engine("pqc_scanner", target, timeout=90)
