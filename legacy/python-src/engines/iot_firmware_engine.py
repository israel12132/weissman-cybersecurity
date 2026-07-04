"""
IoT Firmware Engine — delegated to Rust (fingerprint_engine iot_firmware).
Python only invokes the binary and returns result; no scan logic here.
"""
from __future__ import annotations
from typing import Any
from src.engines._rust_runner import run_rust_engine

def run_iot_firmware(target: str, scope: dict[str, Any] | None = None) -> dict[str, Any]:
    """Run IoT Firmware engine via Rust. Returns { status, findings, message }."""
    return run_rust_engine("iot_firmware", target, timeout=90)
