"""
K8s/Container Attack Engine — delegated to Rust (fingerprint_engine k8s_container).
Delegated to Rust via src.engines.registry — do not add scan logic here.
"""
from __future__ import annotations

from typing import Any

from src.engines.registry import run_engine, warn_legacy_wrapper

warn_legacy_wrapper("k8s_container", __name__)


def run_k8s_container(target: str, scope: dict[str, Any] | None = None) -> dict[str, Any]:
    _ = scope
    return run_engine("k8s_container", target, timeout=90)
