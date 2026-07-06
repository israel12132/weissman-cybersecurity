"""
Attack Surface Management — delegated to Rust (fingerprint_engine asm).
Delegated to Rust via src.engines.registry — do not add scan logic here.
"""
from __future__ import annotations

from typing import Any

from src.engines.registry import run_engine, warn_legacy_wrapper

warn_legacy_wrapper("asm", __name__)


def run_attack_surface_scan(target: str, scope: dict[str, Any] | None = None) -> dict[str, Any]:
    _ = scope
    return run_engine("asm", target, timeout=90)
