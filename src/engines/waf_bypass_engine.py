"""
WAF Bypass Engine — delegated to Rust (fingerprint_engine waf_bypass).
Python only invokes the binary and returns result; no scan logic here.
"""
from __future__ import annotations
from typing import Any
from src.engines._rust_runner import run_rust_engine

def run_waf_bypass(target: str, scope: dict[str, Any] | None = None) -> dict[str, Any]:
    """Run WAF Bypass engine via Rust. Returns { status, findings, message }."""
    return run_rust_engine("waf_bypass", target, timeout=90)
