"""
BLE/RF Engine — delegated to Rust (fingerprint_engine ble_rf).
Delegated to Rust via src.engines.registry — do not add scan logic here.
"""
from __future__ import annotations

from typing import Any

from src.engines.registry import run_engine, warn_legacy_wrapper

warn_legacy_wrapper("ble_rf", __name__)


def run_ble_rf(target: str, scope: dict[str, Any] | None = None) -> dict[str, Any]:
    _ = scope
    return run_engine("ble_rf", target, timeout=90)
