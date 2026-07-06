"""
Zero-Cost AI Fuzzing — delegated to Rust (fingerprint_engine ollama_fuzz).
Delegated to Rust via src.engines.registry — do not add scan logic here.
"""
from __future__ import annotations

from typing import Any

from src.engines.registry import run_engine, warn_legacy_wrapper

warn_legacy_wrapper("ollama_fuzz", __name__)


def run_ollama_fuzz(target: str, scope: dict[str, Any] | None = None) -> dict[str, Any]:
    _ = scope
    return run_engine("ollama_fuzz", target, timeout=90)
