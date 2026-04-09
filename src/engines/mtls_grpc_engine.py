"""
mTLS/gRPC Attack Engine — delegated to Rust (fingerprint_engine mtls_grpc).
Python only invokes the binary and returns result; no scan logic here.
"""
from __future__ import annotations
from typing import Any
from src.engines._rust_runner import run_rust_engine


def run_mtls_grpc(target: str, scope: dict[str, Any] | None = None) -> dict[str, Any]:
    """Run mTLS/gRPC attack scan via Rust. Returns { status, findings, message }."""
    return run_rust_engine("mtls_grpc", target, timeout=30)
