"""
mTLS/gRPC Attack Engine — delegated to Rust (fingerprint_engine mtls_grpc).
Delegated to Rust via src.engines.registry — do not add scan logic here.
"""
from __future__ import annotations

from typing import Any

from src.engines.registry import run_engine, warn_legacy_wrapper

warn_legacy_wrapper("mtls_grpc", __name__)


def run_mtls_grpc(target: str, scope: dict[str, Any] | None = None) -> dict[str, Any]:
    _ = scope
    return run_engine("mtls_grpc", target, timeout=30)
