"""
SBOM Analyzer — delegated to Rust (fingerprint_engine sbom_analyzer).
Delegated to Rust via src.engines.registry — do not add scan logic here.
"""
from __future__ import annotations

from typing import Any

from src.engines.registry import run_engine, warn_legacy_wrapper

warn_legacy_wrapper("sbom_analyzer", __name__)


def run_sbom_analyzer(target: str, scope: dict[str, Any] | None = None) -> dict[str, Any]:
    _ = scope
    return run_engine("sbom_analyzer", target, timeout=60)
