"""
Kerberoasting Engine — delegated to Rust (fingerprint_engine kerberoasting).
Python only invokes the binary and returns result; no scan logic here.
"""
from __future__ import annotations
from typing import Any
from src.engines._rust_runner import run_rust_engine

def run_kerberoasting(target: str, scope: dict[str, Any] | None = None) -> dict[str, Any]:
    """Run Kerberoasting engine via Rust. Returns { status, findings, message }."""
    return run_rust_engine("kerberoasting", target, timeout=90)
