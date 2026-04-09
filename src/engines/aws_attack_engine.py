"""
AWS Attack Engine — delegated to Rust (fingerprint_engine aws_attack).
Python only invokes the binary and returns result; no scan logic here.
"""
from __future__ import annotations
from typing import Any
from src.engines._rust_runner import run_rust_engine


def run_aws_attack(target: str, scope: dict[str, Any] | None = None) -> dict[str, Any]:
    """Run AWS Attack engine via Rust. Returns { status, findings, message }."""
    return run_rust_engine("aws_attack", target, timeout=90)
