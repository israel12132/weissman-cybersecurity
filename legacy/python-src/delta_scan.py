"""
Weissman-cybersecurity Enterprise: Delta-Scanning.
Only notify/alert when there is a CHANGE in attack surface (new port, changed header, new CVE match).
"""
import hashlib
import json
import logging
from typing import Any

from src.database import get_session_factory, AttackSurfaceSnapshotModel

logger = logging.getLogger(__name__)


def _ports_key(ports: list[int]) -> str:
    return json.dumps(sorted(ports), default=str)


def _headers_hash(headers: dict[str, str]) -> str:
    if not headers:
        return ""
    return hashlib.sha256(json.dumps(headers, sort_keys=True).encode()).hexdigest()


def get_snapshot(target_id: str) -> dict[str, Any] | None:
    """Return last snapshot for target or None."""
    try:
        factory = get_session_factory()
        db = factory()
        try:
            row = (
                db.query(AttackSurfaceSnapshotModel)
                .filter(AttackSurfaceSnapshotModel.target_id == target_id)
                .order_by(AttackSurfaceSnapshotModel.updated_at.desc())
                .first()
            )
            if not row:
                return None
            return {
                "ports_json": row.ports_json or "[]",
                "headers_hash": row.headers_hash or "",
                "cve_ids_json": row.cve_ids_json or "[]",
                "assets_json": getattr(row, "assets_json", None) or "[]",
            }
        finally:
            db.close()
    except Exception as e:
        logger.warning("Delta-scan get_snapshot failed: %s", e)
        return None


def get_known_assets(target_id: str) -> list[str]:
    """Return list of known asset identifiers (subdomains, IPs, bucket names) for target."""
    snap = get_snapshot(target_id)
    if not snap:
        return []
    try:
        return json.loads(snap.get("assets_json") or "[]")
    except Exception:
        return []


def has_changed(
    target_id: str,
    ports: list[int] | None = None,
    headers: dict[str, str] | None = None,
    cve_ids: list[str] | None = None,
    assets: list[str] | None = None,
) -> bool:
    """True if no previous snapshot or any of (ports, headers hash, cve_ids) differ."""
    prev = get_snapshot(target_id)
    if prev is None:
        return True
    if ports is not None:
        prev_ports = json.loads(prev["ports_json"] or "[]")
        if _ports_key(ports) != _ports_key(prev_ports):
            return True
    if headers is not None:
        h = _headers_hash(headers)
        if h and h != (prev["headers_hash"] or ""):
            return True
    if cve_ids is not None:
        prev_cves = set(json.loads(prev["cve_ids_json"] or "[]"))
        if set(cve_ids) != prev_cves:
            return True
    if assets is not None:
        prev_assets = set(json.loads(prev.get("assets_json") or "[]"))
        if set(assets) != prev_assets:
            return True
    return False


def save_snapshot(
    target_id: str,
    target_type: str = "client",
    ports: list[int] | None = None,
    headers: dict[str, str] | None = None,
    cve_ids: list[str] | None = None,
    assets: list[str] | None = None,
) -> None:
    """Update stored snapshot for target."""
    try:
        factory = get_session_factory()
        db = factory()
        try:
            row = (
                db.query(AttackSurfaceSnapshotModel)
                .filter(AttackSurfaceSnapshotModel.target_id == target_id)
                .first()
            )
            if not row:
                row = AttackSurfaceSnapshotModel(target_id=target_id, target_type=target_type)
                db.add(row)
            if ports is not None:
                row.ports_json = json.dumps(ports, default=str)
            if headers is not None:
                row.headers_hash = _headers_hash(headers)
            if cve_ids is not None:
                row.cve_ids_json = json.dumps(list(cve_ids), default=str)
            if assets is not None and hasattr(row, "assets_json"):
                row.assets_json = json.dumps(list(assets), default=str)
            db.commit()
        finally:
            db.close()
    except Exception as e:
        logger.warning("Delta-scan save_snapshot failed: %s", e)
