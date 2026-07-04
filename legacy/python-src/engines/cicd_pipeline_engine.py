"""
CI/CD Pipeline Attack Engine — delegated to Rust (fingerprint_engine cicd_pipeline).
Python only invokes the binary and returns result; no scan logic here.
"""
from __future__ import annotations
from typing import Any
from src.engines._rust_runner import run_rust_engine


def run_cicd_pipeline(target: str, scope: dict[str, Any] | None = None) -> dict[str, Any]:
    """Run CI/CD pipeline attack scan via Rust. Returns { status, findings, message }."""
    return run_rust_engine("cicd_pipeline", target, timeout=60)
