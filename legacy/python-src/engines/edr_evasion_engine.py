"""
EDR Evasion Engine — delegated to Rust (fingerprint_engine edr_evasion).
Python only invokes the binary and returns result; no scan logic here.
"""
from __future__ import annotations
from typing import Any
from src.engines._rust_runner import run_rust_engine

def run_edr_evasion(target: str, scope: dict[str, Any] | None = None) -> dict[str, Any]:
    """Run EDR Evasion engine via Rust. Returns { status, findings, message }."""
    return run_rust_engine("edr_evasion", target, timeout=90)
