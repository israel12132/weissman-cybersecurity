"""
GraphQL Attack — delegated to Rust (fingerprint_engine graphql_attack).
Python only invokes the binary and returns result; no scan logic here.
"""
from __future__ import annotations
from typing import Any
from src.engines._rust_runner import run_rust_engine


def run_graphql_attack(target: str, scope: dict[str, Any] | None = None) -> dict[str, Any]:
    """Run GraphQL attack scan via Rust. Returns { status, findings, message }."""
    return run_rust_engine("graphql_attack", target, timeout=90)
