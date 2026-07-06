"""
CI/CD Pipeline Attack Engine — delegated to Rust (fingerprint_engine cicd_pipeline).
Delegated to Rust via src.engines.registry — do not add scan logic here.
"""
from __future__ import annotations

from typing import Any

from src.engines.registry import run_engine, warn_legacy_wrapper

warn_legacy_wrapper("cicd_pipeline", __name__)


def run_cicd_pipeline(target: str, scope: dict[str, Any] | None = None) -> dict[str, Any]:
    _ = scope
    return run_engine("cicd_pipeline", target, timeout=60)
