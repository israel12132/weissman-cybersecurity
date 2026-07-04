"""
BOLA/IDOR — delegated to Rust (fingerprint_engine bola_idor).
Python only invokes the binary and returns result; no scan logic here.
"""
from __future__ import annotations

from typing import Any

from src.engines._rust_runner import run_rust_engine


def run_bola_idor(target: str, scope: dict[str, Any] | None = None) -> dict[str, Any]:
    """Run BOLA/IDOR check via Rust. Returns { status, findings, message }."""
    return run_rust_engine("bola_idor", target)
