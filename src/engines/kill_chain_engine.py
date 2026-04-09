"""
Kill Chain Planner Engine — delegated to Rust (fingerprint_engine kill_chain).
Python only invokes the binary and returns result; no scan logic here.
"""
from __future__ import annotations
from typing import Any
from src.engines._rust_runner import run_rust_engine


def run_kill_chain(target: str, scope: dict[str, Any] | None = None) -> dict[str, Any]:
    """Run Kill Chain Planner engine via Rust. Returns { status, findings, message }."""
    return run_rust_engine("kill_chain", target, timeout=90)
