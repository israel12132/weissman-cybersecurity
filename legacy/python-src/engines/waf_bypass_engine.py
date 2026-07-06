"""
WAF Bypass Engine — delegated to Rust (fingerprint_engine waf_bypass).
Delegated to Rust via src.engines.registry — do not add scan logic here.
"""
from __future__ import annotations

from typing import Any

from src.engines.registry import run_engine, warn_legacy_wrapper

warn_legacy_wrapper("waf_bypass", __name__)


def run_waf_bypass(target: str, scope: dict[str, Any] | None = None) -> dict[str, Any]:
    _ = scope
    return run_engine("waf_bypass", target, timeout=90)
