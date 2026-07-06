"""
IoT Firmware Engine — delegated to Rust (fingerprint_engine iot_firmware).
Delegated to Rust via src.engines.registry — do not add scan logic here.
"""
from __future__ import annotations

from typing import Any

from src.engines.registry import run_engine, warn_legacy_wrapper

warn_legacy_wrapper("iot_firmware", __name__)


def run_iot_firmware(target: str, scope: dict[str, Any] | None = None) -> dict[str, Any]:
    _ = scope
    return run_engine("iot_firmware", target, timeout=90)
