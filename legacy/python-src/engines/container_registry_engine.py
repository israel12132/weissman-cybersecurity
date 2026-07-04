"""
Container Registry Engine — delegated to Rust (fingerprint_engine container_registry).
Python only invokes the binary and returns result; no scan logic here.
"""
from __future__ import annotations
from typing import Any
from src.engines._rust_runner import run_rust_engine


def run_container_registry(target: str, scope: dict[str, Any] | None = None) -> dict[str, Any]:
    """Run container registry scan via Rust. Returns { status, findings, message }."""
    return run_rust_engine("container_registry", target, timeout=60)
