"""
BLE/RF Engine — delegated to Rust (fingerprint_engine ble_rf).
Python only invokes the binary and returns result; no scan logic here.
"""
from __future__ import annotations
from typing import Any
from src.engines._rust_runner import run_rust_engine

def run_ble_rf(target: str, scope: dict[str, Any] | None = None) -> dict[str, Any]:
    """Run BLE/RF engine via Rust. Returns { status, findings, message }."""
    return run_rust_engine("ble_rf", target, timeout=90)
