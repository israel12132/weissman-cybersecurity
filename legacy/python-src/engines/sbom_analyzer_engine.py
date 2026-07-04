"""
SBOM Analyzer — delegated to Rust (fingerprint_engine sbom_analyzer).
Python only invokes the binary and returns result; no scan logic here.
"""
from __future__ import annotations
from typing import Any
from src.engines._rust_runner import run_rust_engine


def run_sbom_analyzer(target: str, scope: dict[str, Any] | None = None) -> dict[str, Any]:
    """Run SBOM analysis via Rust. Returns { status, findings, message }."""
    return run_rust_engine("sbom_analyzer", target, timeout=60)
