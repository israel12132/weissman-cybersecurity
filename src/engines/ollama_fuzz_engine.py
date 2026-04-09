"""
Zero-Cost AI Fuzzing — delegated to Rust (fingerprint_engine ollama_fuzz).
Python only invokes the binary and returns result; no scan logic here.
"""
from __future__ import annotations

from typing import Any

from src.engines._rust_runner import run_rust_engine


def run_ollama_fuzz(target: str, scope: dict[str, Any] | None = None) -> dict[str, Any]:
    """Run Ollama fuzz via Rust. Returns { status, findings, message }."""
    return run_rust_engine("ollama_fuzz", target, timeout=90)
