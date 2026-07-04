"""
OAST/OOB Engine — delegated to Rust (fingerprint_engine oast_oob).
Python only invokes the binary and returns result; no scan logic here.
"""
from __future__ import annotations
from typing import Any
from src.engines._rust_runner import run_rust_engine


def run_oast_oob(target: str, scope: dict[str, Any] | None = None) -> dict[str, Any]:
    """Run OAST/OOB interaction testing via Rust. Returns { status, findings, message }."""
    return run_rust_engine("oast_oob", target, timeout=60)
