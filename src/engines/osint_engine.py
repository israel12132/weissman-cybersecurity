"""
Deep OSINT — delegated to Rust (fingerprint_engine osint).
Python only invokes the binary and returns result; no scan logic here.
"""
from __future__ import annotations

from typing import Any

from src.engines._rust_runner import run_rust_engine


def run_osint_crawl(target: str, scope: dict[str, Any] | None = None) -> dict[str, Any]:
    """Run OSINT crawl via Rust. Returns { status, findings, message }."""
    return run_rust_engine("osint", target)
