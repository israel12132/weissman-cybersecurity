"""
AWS Attack Engine — delegated to Rust (fingerprint_engine aws_attack).
Delegated to Rust via src.engines.registry — do not add scan logic here.
"""
from __future__ import annotations

from typing import Any

from src.engines.registry import run_engine, warn_legacy_wrapper

warn_legacy_wrapper("aws_attack", __name__)


def run_aws_attack(target: str, scope: dict[str, Any] | None = None) -> dict[str, Any]:
    _ = scope
    return run_engine("aws_attack", target, timeout=90)
