"""
BGP/DNS Hijacking Detector — delegated to Rust (fingerprint_engine bgp_dns_hijacking).
Delegated to Rust via src.engines.registry — do not add scan logic here.
"""
from __future__ import annotations

from typing import Any

from src.engines.registry import run_engine, warn_legacy_wrapper

warn_legacy_wrapper("bgp_dns_hijacking", __name__)


def run_bgp_dns_hijacking(target: str, scope: dict[str, Any] | None = None) -> dict[str, Any]:
    _ = scope
    return run_engine("bgp_dns_hijacking", target, timeout=30)
