"""
Deep OSINT — delegated to Rust (fingerprint_engine osint).
Delegated to Rust via src.engines.registry — do not add scan logic here.
"""
from __future__ import annotations

from typing import Any

from src.engines.registry import run_engine, warn_legacy_wrapper

warn_legacy_wrapper("osint", __name__)


def run_osint_crawl(target: str, scope: dict[str, Any] | None = None) -> dict[str, Any]:
    _ = scope
    return run_engine("osint", target, timeout=120)
