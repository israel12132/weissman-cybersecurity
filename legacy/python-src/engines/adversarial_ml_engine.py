"""
Adversarial ML Engine — delegated to Rust (fingerprint_engine adversarial_ml).
Delegated to Rust via src.engines.registry — do not add scan logic here.
"""
from __future__ import annotations

from typing import Any

from src.engines.registry import run_engine, warn_legacy_wrapper

warn_legacy_wrapper("adversarial_ml", __name__)


def run_adversarial_ml(target: str, scope: dict[str, Any] | None = None) -> dict[str, Any]:
    _ = scope
    return run_engine("adversarial_ml", target, timeout=90)
