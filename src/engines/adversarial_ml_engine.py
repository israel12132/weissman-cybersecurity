"""
Adversarial ML Engine — delegated to Rust (fingerprint_engine adversarial_ml).
Python only invokes the binary and returns result; no scan logic here.
"""
from __future__ import annotations
from typing import Any
from src.engines._rust_runner import run_rust_engine


def run_adversarial_ml(target: str, scope: dict[str, Any] | None = None) -> dict[str, Any]:
    """Run Adversarial ML engine via Rust. Returns { status, findings, message }."""
    return run_rust_engine("adversarial_ml", target, timeout=90)
