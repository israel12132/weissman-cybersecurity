"""
Password Spray Engine — delegated to Rust (fingerprint_engine password_spray).
Python only invokes the binary and returns result; no scan logic here.
"""
from __future__ import annotations
from typing import Any
from src.engines._rust_runner import run_rust_engine

def run_password_spray(target: str, scope: dict[str, Any] | None = None) -> dict[str, Any]:
    """Run Password Spray engine via Rust. Returns { status, findings, message }."""
    return run_rust_engine("password_spray", target, timeout=90)
