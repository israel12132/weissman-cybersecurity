"""
SAML Attack Engine — delegated to Rust (fingerprint_engine saml_attack).
Delegated to Rust via src.engines.registry — do not add scan logic here.
"""
from __future__ import annotations

from typing import Any

from src.engines.registry import run_engine, warn_legacy_wrapper

warn_legacy_wrapper("saml_attack", __name__)


def run_saml_attack(target: str, scope: dict[str, Any] | None = None) -> dict[str, Any]:
    _ = scope
    return run_engine("saml_attack", target, timeout=90)
