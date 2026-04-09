"""
OAuth/OIDC Attack — delegated to Rust (fingerprint_engine oauth_oidc).
Python only invokes the binary and returns result; no scan logic here.
"""
from __future__ import annotations
from typing import Any
from src.engines._rust_runner import run_rust_engine


def run_oauth_oidc(target: str, scope: dict[str, Any] | None = None) -> dict[str, Any]:
    """Run OAuth/OIDC attack scan via Rust. Returns { status, findings, message }."""
    return run_rust_engine("oauth_oidc", target, timeout=90)
