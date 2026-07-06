"""
EDR Evasion Engine — delegated to Rust (fingerprint_engine edr_evasion).
Delegated to Rust via src.engines.registry — do not add scan logic here.
"""
from __future__ import annotations

from typing import Any

from src.engines.registry import run_engine, warn_legacy_wrapper

warn_legacy_wrapper("edr_evasion", __name__)


def run_edr_evasion(target: str, scope: dict[str, Any] | None = None) -> dict[str, Any]:
    _ = scope
    return run_engine("edr_evasion", target, timeout=90)
