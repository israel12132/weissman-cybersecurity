"""
SMB/NetBIOS Engine — delegated to Rust (fingerprint_engine smb_netbios).
Python only invokes the binary and returns result; no scan logic here.
"""
from __future__ import annotations
from typing import Any
from src.engines._rust_runner import run_rust_engine


def run_smb_netbios(target: str, scope: dict[str, Any] | None = None) -> dict[str, Any]:
    """Run SMB/NetBIOS scan via Rust. Returns { status, findings, message }."""
    return run_rust_engine("smb_netbios", target, timeout=30)
