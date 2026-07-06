"""
OAuth/OIDC Attack — delegated to Rust (fingerprint_engine oauth_oidc).
Delegated to Rust via src.engines.registry — do not add scan logic here.
"""
from __future__ import annotations

from typing import Any

from src.engines.registry import run_engine, warn_legacy_wrapper

warn_legacy_wrapper("oauth_oidc", __name__)


def run_oauth_oidc(target: str, scope: dict[str, Any] | None = None) -> dict[str, Any]:
    _ = scope
    return run_engine("oauth_oidc", target, timeout=90)
