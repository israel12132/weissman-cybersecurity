"""
PQC Scanner Engine — delegated to Rust (fingerprint_engine pqc_scanner).
Delegated to Rust via src.engines.registry — do not add scan logic here.
"""
from __future__ import annotations

from typing import Any

from src.engines.registry import run_engine, warn_legacy_wrapper

warn_legacy_wrapper("pqc_scanner", __name__)


def run_pqc_scanner(target: str, scope: dict[str, Any] | None = None) -> dict[str, Any]:
    _ = scope
    return run_engine("pqc_scanner", target, timeout=90)
