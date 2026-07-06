"""
Verified Supply Chain Auditing — delegated to Rust (fingerprint_engine supply_chain).
Delegated to Rust via src.engines.registry — do not add scan logic here.
"""
from __future__ import annotations

from typing import Any

from src.engines.registry import run_engine, warn_legacy_wrapper

warn_legacy_wrapper("supply_chain", __name__)


def run_supply_chain_audit(target: str, scope: dict[str, Any] | None = None) -> dict[str, Any]:
    _ = scope
    return run_engine("supply_chain", target, timeout=120)
