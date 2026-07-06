"""
Zero-Day Prediction Engine — delegated to Rust (fingerprint_engine zero_day_prediction).
Delegated to Rust via src.engines.registry — do not add scan logic here.
"""
from __future__ import annotations

from typing import Any

from src.engines.registry import run_engine, warn_legacy_wrapper

warn_legacy_wrapper("zero_day_prediction", __name__)


def run_zero_day_prediction(target: str, scope: dict[str, Any] | None = None) -> dict[str, Any]:
    _ = scope
    return run_engine("zero_day_prediction", target, timeout=60)
