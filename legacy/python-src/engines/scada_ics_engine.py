"""
SCADA/ICS Engine — delegated to Rust (fingerprint_engine scada_ics).
Delegated to Rust via src.engines.registry — do not add scan logic here.
"""
from __future__ import annotations

from typing import Any

from src.engines.registry import run_engine, warn_legacy_wrapper

warn_legacy_wrapper("scada_ics", __name__)


def run_scada_ics(target: str, scope: dict[str, Any] | None = None) -> dict[str, Any]:
    _ = scope
    return run_engine("scada_ics", target, timeout=90)
