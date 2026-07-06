"""
SSTI Attack — delegated to Rust (fingerprint_engine ssti).
Delegated to Rust via src.engines.registry — do not add scan logic here.
"""
from __future__ import annotations

from typing import Any

from src.engines.registry import run_engine, warn_legacy_wrapper

warn_legacy_wrapper("ssti", __name__)


def run_ssti(target: str, scope: dict[str, Any] | None = None) -> dict[str, Any]:
    _ = scope
    return run_engine("ssti", target, timeout=90)
