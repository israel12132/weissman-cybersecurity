"""
Kill Chain Planner Engine — delegated to Rust (fingerprint_engine kill_chain).
Delegated to Rust via src.engines.registry — do not add scan logic here.
"""
from __future__ import annotations

from typing import Any

from src.engines.registry import run_engine, warn_legacy_wrapper

warn_legacy_wrapper("kill_chain", __name__)


def run_kill_chain(target: str, scope: dict[str, Any] | None = None) -> dict[str, Any]:
    _ = scope
    return run_engine("kill_chain", target, timeout=90)
