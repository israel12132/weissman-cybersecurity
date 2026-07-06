"""
HTTP Request Smuggling — delegated to Rust (fingerprint_engine http_smuggling).
Delegated to Rust via src.engines.registry — do not add scan logic here.
"""
from __future__ import annotations

from typing import Any

from src.engines.registry import run_engine, warn_legacy_wrapper

warn_legacy_wrapper("http_smuggling", __name__)


def run_http_smuggling(target: str, scope: dict[str, Any] | None = None) -> dict[str, Any]:
    _ = scope
    return run_engine("http_smuggling", target, timeout=90)
