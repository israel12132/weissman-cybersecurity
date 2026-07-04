"""
Attack Surface Management — delegated to Rust (fingerprint_engine asm).
Python only invokes the binary and returns result; no scan logic here.
"""
from __future__ import annotations

from typing import Any

from src.engines._rust_runner import run_rust_engine


def run_attack_surface_scan(target: str, scope: dict[str, Any] | None = None) -> dict[str, Any]:
    """Run ASM scan via Rust. Returns { status, findings, message }."""
    return run_rust_engine("asm", target, timeout=90)
