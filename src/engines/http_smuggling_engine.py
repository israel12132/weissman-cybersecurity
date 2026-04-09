"""
HTTP Request Smuggling — delegated to Rust (fingerprint_engine http_smuggling).
Python only invokes the binary and returns result; no scan logic here.
"""
from __future__ import annotations
from typing import Any
from src.engines._rust_runner import run_rust_engine


def run_http_smuggling(target: str, scope: dict[str, Any] | None = None) -> dict[str, Any]:
    """Run HTTP smuggling scan via Rust. Returns { status, findings, message }."""
    return run_rust_engine("http_smuggling", target, timeout=90)
