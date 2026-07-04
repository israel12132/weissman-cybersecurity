"""
SSTI Attack — delegated to Rust (fingerprint_engine ssti).
Python only invokes the binary and returns result; no scan logic here.
"""
from __future__ import annotations
from typing import Any
from src.engines._rust_runner import run_rust_engine


def run_ssti(target: str, scope: dict[str, Any] | None = None) -> dict[str, Any]:
    """Run SSTI scan via Rust. Returns { status, findings, message }."""
    return run_rust_engine("ssti", target, timeout=90)
