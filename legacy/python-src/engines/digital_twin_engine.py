"""
Digital Twin Attack Simulator — delegated to Rust (fingerprint_engine digital_twin).
Delegated to Rust via src.engines.registry — do not add scan logic here.
"""
from __future__ import annotations

from typing import Any

from src.engines.registry import run_engine, warn_legacy_wrapper

warn_legacy_wrapper("digital_twin", __name__)


def run_digital_twin(target: str, scope: dict[str, Any] | None = None) -> dict[str, Any]:
    _ = scope
    return run_engine("digital_twin", target, timeout=60)
