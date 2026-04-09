"""
File Upload Attack — delegated to Rust (fingerprint_engine file_upload).
Python only invokes the binary and returns result; no scan logic here.
"""
from __future__ import annotations
from typing import Any
from src.engines._rust_runner import run_rust_engine


def run_file_upload(target: str, scope: dict[str, Any] | None = None) -> dict[str, Any]:
    """Run file upload attack scan via Rust. Returns { status, findings, message }."""
    return run_rust_engine("file_upload", target, timeout=90)
