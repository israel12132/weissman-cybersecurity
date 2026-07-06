"""
Deception/Honeypot Intelligence — delegated to Rust (fingerprint_engine deception_honeypot).
Delegated to Rust via src.engines.registry — do not add scan logic here.
"""
from __future__ import annotations

from typing import Any

from src.engines.registry import run_engine, warn_legacy_wrapper

warn_legacy_wrapper("deception_honeypot", __name__)


def run_deception_honeypot(target: str, scope: dict[str, Any] | None = None) -> dict[str, Any]:
    _ = scope
    return run_engine("deception_honeypot", target, timeout=30)
