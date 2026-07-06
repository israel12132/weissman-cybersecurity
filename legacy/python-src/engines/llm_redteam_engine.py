"""
LLM Red-Team Engine — delegated to Rust (fingerprint_engine llm_redteam).
Delegated to Rust via src.engines.registry — do not add scan logic here.
"""
from __future__ import annotations

from typing import Any

from src.engines.registry import run_engine, warn_legacy_wrapper

warn_legacy_wrapper("llm_redteam", __name__)


def run_llm_redteam(target: str, scope: dict[str, Any] | None = None) -> dict[str, Any]:
    _ = scope
    return run_engine("llm_redteam", target, timeout=90)
