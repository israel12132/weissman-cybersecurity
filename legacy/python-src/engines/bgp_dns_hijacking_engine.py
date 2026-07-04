"""
BGP/DNS Hijacking Detector — delegated to Rust (fingerprint_engine bgp_dns_hijacking).
Python only invokes the binary and returns result; no scan logic here.
"""
from __future__ import annotations
from typing import Any
from src.engines._rust_runner import run_rust_engine


def run_bgp_dns_hijacking(target: str, scope: dict[str, Any] | None = None) -> dict[str, Any]:
    """Run BGP/DNS hijacking detection via Rust. Returns { status, findings, message }."""
    return run_rust_engine("bgp_dns_hijacking", target, timeout=30)
