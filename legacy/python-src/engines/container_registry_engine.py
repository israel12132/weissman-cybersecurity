"""
Container Registry Engine — delegated to Rust (fingerprint_engine container_registry).
Delegated to Rust via src.engines.registry — do not add scan logic here.
"""
from __future__ import annotations

from typing import Any

from src.engines.registry import run_engine, warn_legacy_wrapper

warn_legacy_wrapper("container_registry", __name__)


def run_container_registry(target: str, scope: dict[str, Any] | None = None) -> dict[str, Any]:
    _ = scope
    return run_engine("container_registry", target, timeout=60)
