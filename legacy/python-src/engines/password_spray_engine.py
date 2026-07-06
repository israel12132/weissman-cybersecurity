"""
Password Spray Engine — delegated to Rust (fingerprint_engine password_spray).
Delegated to Rust via src.engines.registry — do not add scan logic here.
"""
from __future__ import annotations

from typing import Any

from src.engines.registry import run_engine, warn_legacy_wrapper

warn_legacy_wrapper("password_spray", __name__)


def run_password_spray(target: str, scope: dict[str, Any] | None = None) -> dict[str, Any]:
    _ = scope
    return run_engine("password_spray", target, timeout=90)
