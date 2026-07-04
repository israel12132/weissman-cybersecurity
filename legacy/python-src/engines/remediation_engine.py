"""
Genesis Protocol — remediation / vaccine vault (Python side).

Reads `genesis_vaccine_vault` for tech-stack knowledge match during onboarding or jobs.
Authoritative storage and council validation run in the Rust fingerprint_engine worker; this module
is for orchestration code that shares the same DATABASE_URL.

Optional: set ``WEISSMAN_GENESIS_SHM_INDEX=1`` to mmap a local cache file under ``/dev/shm`` (Linux)
for repeated lookups in the same process — not a cross-process shared-memory graph.
"""
from __future__ import annotations

import hashlib
import json
import logging
import os
from typing import Any

logger = logging.getLogger(__name__)


def tech_fingerprint_from_stack(stack: str | list[str] | dict[str, Any]) -> str:
    """Stable SHA-256 hex digest aligned with Rust `eternal_fuzz::tech_fingerprint_for_chain` style."""
    if isinstance(stack, dict):
        normalized = json.dumps(stack, sort_keys=True, separators=(",", ":"))
    elif isinstance(stack, list):
        normalized = "|".join(sorted(str(x).strip() for x in stack if str(x).strip()))
    else:
        normalized = str(stack).strip()
    return hashlib.sha256(normalized.encode()).hexdigest()


def knowledge_match_sync(tenant_id: int, tech_fingerprint: str) -> list[dict[str, Any]]:
    """
    Query preemptive validated rows for a fingerprint. Requires PostgreSQL ``DATABASE_URL``.
    """
    url = (os.getenv("DATABASE_URL") or "").strip()
    if not url or "postgresql" not in url.replace("+asyncpg", ""):
        logger.warning("knowledge_match_sync: DATABASE_URL not set or not Postgres; skipping")
        return []
    try:
        from sqlalchemy import text
        from src.database import get_engine

        engine = get_engine()
        fp = tech_fingerprint.strip()
        if not fp:
            return []
        sql = text(
            """
            SELECT id, component_ref, severity, detection_signature,
                   remediation_patch, attack_chain_json, created_at
            FROM genesis_vaccine_vault
            WHERE tenant_id = :tid
              AND tech_fingerprint = :fp
              AND preemptive_validated = true
            ORDER BY id DESC
            LIMIT 64
            """
        )
        with engine.connect() as conn:
            rows = conn.execute(sql, {"tid": tenant_id, "fp": fp}).mappings().all()
        return [dict(r) for r in rows]
    except Exception as e:
        logger.warning("knowledge_match_sync failed: %s", e)
        return []


def after_validated_chain_record(record: dict[str, Any]) -> None:
    """
    Hook after Rust stores a vault row (e.g. from a webhook or shared queue). Extend to enqueue
    PoE / heal_request via HTTP API if needed.
    """
    _ = record
    logger.info("after_validated_chain_record: extend for PoE/heal HTTP enqueue if required")


def warm_process_local_cache(matches: list[dict[str, Any]], cache_path: str | None = None) -> None:
    """
    Write matches JSON to a path (default ``/dev/shm/weissman_genesis_vault_cache.json``) for
    sub-ms re-read in the same host process; optional ``WEISSMAN_GENESIS_SHM_INDEX=1``.
    """
    if os.getenv("WEISSMAN_GENESIS_SHM_INDEX", "").strip().lower() not in ("1", "true", "yes"):
        return
    path = cache_path or "/dev/shm/weissman_genesis_vault_cache.json"
    try:
        with open(path, "w", encoding="utf-8") as f:
            json.dump(matches, f, separators=(",", ":"))
    except OSError as e:
        logger.debug("warm_process_local_cache skip %s: %s", path, e)
