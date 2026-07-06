"""
File Upload Attack — delegated to Rust (fingerprint_engine file_upload).
Delegated to Rust via src.engines.registry — do not add scan logic here.
"""
from __future__ import annotations

from typing import Any

from src.engines.registry import run_engine, warn_legacy_wrapper

warn_legacy_wrapper("file_upload", __name__)


def run_file_upload(target: str, scope: dict[str, Any] | None = None) -> dict[str, Any]:
    _ = scope
    return run_engine("file_upload", target, timeout=90)
