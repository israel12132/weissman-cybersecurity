"""
Timing Side-Channel Engine — delegated to Rust (fingerprint_engine timing_sidechannel).
Python only invokes the binary and returns result; no scan logic here.
"""
from __future__ import annotations
from typing import Any
from src.engines._rust_runner import run_rust_engine

def run_timing_sidechannel(target: str, scope: dict[str, Any] | None = None) -> dict[str, Any]:
    """Run Timing Side-Channel engine via Rust. Returns { status, findings, message }."""
    return run_rust_engine("timing_sidechannel", target, timeout=90)
