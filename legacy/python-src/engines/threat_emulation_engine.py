"""
Threat Emulation Engine — delegated to Rust (fingerprint_engine threat_emulation).
Delegated to Rust via src.engines.registry — do not add scan logic here.
"""
from __future__ import annotations

from typing import Any

from src.engines.registry import run_engine, warn_legacy_wrapper

warn_legacy_wrapper("threat_emulation", __name__)


def run_threat_emulation(target: str, scope: dict[str, Any] | None = None) -> dict[str, Any]:
    _ = scope
    return run_engine("threat_emulation", target, timeout=60)
