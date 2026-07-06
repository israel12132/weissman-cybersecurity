"""
OAST/OOB Engine — delegated to Rust (fingerprint_engine oast_oob).
Delegated to Rust via src.engines.registry — do not add scan logic here.
"""
from __future__ import annotations

from typing import Any

from src.engines.registry import run_engine, warn_legacy_wrapper

warn_legacy_wrapper("oast_oob", __name__)


def run_oast_oob(target: str, scope: dict[str, Any] | None = None) -> dict[str, Any]:
    _ = scope
    return run_engine("oast_oob", target, timeout=60)
