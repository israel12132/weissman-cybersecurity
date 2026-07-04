"""
Cache Poisoning — delegated to Rust (fingerprint_engine cache_poisoning).
Python only invokes the binary and returns result; no scan logic here.
"""
from __future__ import annotations
from typing import Any
from src.engines._rust_runner import run_rust_engine


def run_cache_poisoning(target: str, scope: dict[str, Any] | None = None) -> dict[str, Any]:
    """Run cache poisoning scan via Rust. Returns { status, findings, message }."""
    return run_rust_engine("cache_poisoning", target, timeout=90)
