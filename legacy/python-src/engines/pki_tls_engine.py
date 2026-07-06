"""
PKI/TLS Engine — delegated to Rust (fingerprint_engine pki_tls).
Delegated to Rust via src.engines.registry — do not add scan logic here.
"""
from __future__ import annotations

from typing import Any

from src.engines.registry import run_engine, warn_legacy_wrapper

warn_legacy_wrapper("pki_tls", __name__)


def run_pki_tls(target: str, scope: dict[str, Any] | None = None) -> dict[str, Any]:
    _ = scope
    return run_engine("pki_tls", target, timeout=90)
