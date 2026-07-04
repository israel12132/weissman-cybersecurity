"""
Verified Supply Chain Auditing — delegated to Rust (fingerprint_engine supply_chain).
Python only invokes the binary and returns result; no scan logic here.
"""
from __future__ import annotations

from typing import Any

from src.engines._rust_runner import run_rust_engine


def run_supply_chain_audit(target: str, scope: dict[str, Any] | None = None) -> dict[str, Any]:
    """Run supply chain audit via Rust. Returns { status, findings, message }."""
    return run_rust_engine("supply_chain", target)
