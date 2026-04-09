"""
IaC Misconfig Engine — delegated to Rust (fingerprint_engine iac_misconfig).
Python only invokes the binary and returns result; no scan logic here.
"""
from __future__ import annotations
from typing import Any
from src.engines._rust_runner import run_rust_engine


def run_iac_misconfig(target: str, scope: dict[str, Any] | None = None) -> dict[str, Any]:
    """Run IaC Misconfig engine via Rust. Returns { status, findings, message }."""
    return run_rust_engine("iac_misconfig", target, timeout=90)
