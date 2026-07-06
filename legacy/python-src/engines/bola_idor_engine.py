"""
BOLA/IDOR — delegated to Rust (fingerprint_engine bola_idor).
Delegated to Rust via src.engines.registry — do not add scan logic here.
"""
from __future__ import annotations

from typing import Any

from src.engines.registry import run_engine, warn_legacy_wrapper

warn_legacy_wrapper("bola_idor", __name__)


def run_bola_idor(target: str, scope: dict[str, Any] | None = None) -> dict[str, Any]:
    _ = scope
    return run_engine("bola_idor", target, timeout=120)
