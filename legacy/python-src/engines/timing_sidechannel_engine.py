"""
Timing Side-Channel Engine — delegated to Rust (fingerprint_engine timing_sidechannel).
Delegated to Rust via src.engines.registry — do not add scan logic here.
"""
from __future__ import annotations

from typing import Any

from src.engines.registry import run_engine, warn_legacy_wrapper

warn_legacy_wrapper("timing_sidechannel", __name__)


def run_timing_sidechannel(target: str, scope: dict[str, Any] | None = None) -> dict[str, Any]:
    _ = scope
    return run_engine("timing_sidechannel", target, timeout=90)
