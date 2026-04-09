"""
Typosquatting Active Monitor — delegated to Rust (fingerprint_engine typosquatting_monitor).
Python only invokes the binary and returns result; no scan logic here.
"""
from __future__ import annotations
from typing import Any
from src.engines._rust_runner import run_rust_engine


def run_typosquatting_monitor(target: str, scope: dict[str, Any] | None = None) -> dict[str, Any]:
    """Run typosquatting monitor via Rust. Returns { status, findings, message }."""
    return run_rust_engine("typosquatting_monitor", target, timeout=90)
