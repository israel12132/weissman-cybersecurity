"""
PKI/TLS Engine — delegated to Rust (fingerprint_engine pki_tls).
Python only invokes the binary and returns result; no scan logic here.
"""
from __future__ import annotations
from typing import Any
from src.engines._rust_runner import run_rust_engine

def run_pki_tls(target: str, scope: dict[str, Any] | None = None) -> dict[str, Any]:
    """Run PKI/TLS engine via Rust. Returns { status, findings, message }."""
    return run_rust_engine("pki_tls", target, timeout=90)
