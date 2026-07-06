"""
Cache Poisoning — delegated to Rust (fingerprint_engine cache_poisoning).
Delegated to Rust via src.engines.registry — do not add scan logic here.
"""
from __future__ import annotations

from typing import Any

from src.engines.registry import run_engine, warn_legacy_wrapper

warn_legacy_wrapper("cache_poisoning", __name__)


def run_cache_poisoning(target: str, scope: dict[str, Any] | None = None) -> dict[str, Any]:
    _ = scope
    return run_engine("cache_poisoning", target, timeout=90)
