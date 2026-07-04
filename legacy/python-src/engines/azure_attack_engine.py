"""
Azure Attack Engine — delegated to Rust (fingerprint_engine azure_attack).
Python only invokes the binary and returns result; no scan logic here.
"""
from __future__ import annotations
from typing import Any
from src.engines._rust_runner import run_rust_engine


def run_azure_attack(target: str, scope: dict[str, Any] | None = None) -> dict[str, Any]:
    """Run Azure Attack engine via Rust. Returns { status, findings, message }."""
    return run_rust_engine("azure_attack", target, timeout=90)
