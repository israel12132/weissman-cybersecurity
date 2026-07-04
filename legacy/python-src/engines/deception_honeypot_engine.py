"""
Deception/Honeypot Intelligence — delegated to Rust (fingerprint_engine deception_honeypot).
Python only invokes the binary and returns result; no scan logic here.
"""
from __future__ import annotations
from typing import Any
from src.engines._rust_runner import run_rust_engine


def run_deception_honeypot(target: str, scope: dict[str, Any] | None = None) -> dict[str, Any]:
    """Run honeypot intelligence scan via Rust. Returns { status, findings, message }."""
    return run_rust_engine("deception_honeypot", target, timeout=30)
