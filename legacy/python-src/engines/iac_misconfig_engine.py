"""
IaC Misconfig Engine — delegated to Rust (fingerprint_engine iac_misconfig).
Delegated to Rust via src.engines.registry — do not add scan logic here.
"""
from __future__ import annotations

from typing import Any

from src.engines.registry import run_engine, warn_legacy_wrapper

warn_legacy_wrapper("iac_misconfig", __name__)


def run_iac_misconfig(target: str, scope: dict[str, Any] | None = None) -> dict[str, Any]:
    _ = scope
    return run_engine("iac_misconfig", target, timeout=90)
