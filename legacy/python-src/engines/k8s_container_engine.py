"""
K8s/Container Attack Engine — delegated to Rust (fingerprint_engine k8s_container).
Python only invokes the binary and returns result; no scan logic here.
"""
from __future__ import annotations
from typing import Any
from src.engines._rust_runner import run_rust_engine


def run_k8s_container(target: str, scope: dict[str, Any] | None = None) -> dict[str, Any]:
    """Run K8s/Container Attack engine via Rust. Returns { status, findings, message }."""
    return run_rust_engine("k8s_container", target, timeout=90)
