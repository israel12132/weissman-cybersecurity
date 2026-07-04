"""
GCP Attack Engine — delegated to Rust (fingerprint_engine gcp_attack).
Python only invokes the binary and returns result; no scan logic here.
"""
from __future__ import annotations
from typing import Any
from src.engines._rust_runner import run_rust_engine


def run_gcp_attack(target: str, scope: dict[str, Any] | None = None) -> dict[str, Any]:
    """Run GCP Attack engine via Rust. Returns { status, findings, message }."""
    return run_rust_engine("gcp_attack", target, timeout=90)
