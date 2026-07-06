"""
SMB/NetBIOS Engine — delegated to Rust (fingerprint_engine smb_netbios).
Delegated to Rust via src.engines.registry — do not add scan logic here.
"""
from __future__ import annotations

from typing import Any

from src.engines.registry import run_engine, warn_legacy_wrapper

warn_legacy_wrapper("smb_netbios", __name__)


def run_smb_netbios(target: str, scope: dict[str, Any] | None = None) -> dict[str, Any]:
    _ = scope
    return run_engine("smb_netbios", target, timeout=30)
