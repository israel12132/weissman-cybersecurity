"""
SSRF Advanced — delegated to Rust (fingerprint_engine ssrf_advanced).
Python only invokes the binary and returns result; no scan logic here.
"""
from __future__ import annotations
from typing import Any
from src.engines._rust_runner import run_rust_engine


def run_ssrf_advanced(target: str, scope: dict[str, Any] | None = None) -> dict[str, Any]:
    """Run SSRF advanced scan via Rust. Returns { status, findings, message }."""
    return run_rust_engine("ssrf_advanced", target, timeout=90)
