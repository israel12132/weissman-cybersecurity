"""
Prototype Pollution — delegated to Rust (fingerprint_engine prototype_pollution).
Python only invokes the binary and returns result; no scan logic here.
"""
from __future__ import annotations
from typing import Any
from src.engines._rust_runner import run_rust_engine


def run_prototype_pollution(target: str, scope: dict[str, Any] | None = None) -> dict[str, Any]:
    """Run prototype pollution scan via Rust. Returns { status, findings, message }."""
    return run_rust_engine("prototype_pollution", target, timeout=90)
