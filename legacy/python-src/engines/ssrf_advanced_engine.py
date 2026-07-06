"""
SSRF Advanced — delegated to Rust (fingerprint_engine ssrf_advanced).
Delegated to Rust via src.engines.registry — do not add scan logic here.
"""
from __future__ import annotations

from typing import Any

from src.engines.registry import run_engine, warn_legacy_wrapper

warn_legacy_wrapper("ssrf_advanced", __name__)


def run_ssrf_advanced(target: str, scope: dict[str, Any] | None = None) -> dict[str, Any]:
    _ = scope
    return run_engine("ssrf_advanced", target, timeout=90)
