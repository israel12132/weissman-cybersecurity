"""
Weissman-cybersecurity: Data sovereignty (GDPR / regional compliance).
WEISSMAN_REGION restricts data storage and scan origination to the configured region
(e.g. EU-West traffic must not touch US-East logic).
"""
from __future__ import annotations

import logging
import os
from typing import Any

logger = logging.getLogger(__name__)

VALID_REGIONS = frozenset({"EU-West", "EU-East", "US-East", "US-West", "APAC", ""})


def get_current_region() -> str:
    """Deployment region from WEISSMAN_REGION (e.g. EU-West, US-East). Empty = no restriction."""
    r = (os.getenv("WEISSMAN_REGION") or "").strip()
    return r


def get_tenant_region(tenant_id: int | None, db_session: Any = None) -> str:
    """Return tenant's data residency region from DB (tenants.settings_json or tenants.region). Empty = any."""
    if tenant_id is None:
        return ""
    try:
        from src.database import TenantModel, get_session_factory
        factory = get_session_factory()
        db = factory()
        try:
            t = db.query(TenantModel).filter(TenantModel.id == int(tenant_id)).first()
            if not t:
                return ""
            region = getattr(t, "region", None) or ""
            if region:
                return (region or "").strip()
            import json
            settings = json.loads(getattr(t, "settings_json", None) or "{}")
            return (settings.get("region") or "").strip()
        finally:
            db.close()
    except Exception as e:
        logger.debug("get_tenant_region: %s", e)
    return ""


def should_process_tenant(tenant_id: int | None, db_session: Any = None) -> bool:
    """
    True if orchestrator/workers may process this tenant in the current deployment.
    EU-West deployment must not process US-East tenant data (data sovereignty).
    """
    current = get_current_region()
    if not current:
        return True
    tenant_r = get_tenant_region(tenant_id, db_session)
    if not tenant_r:
        return True
    return current.lower() == tenant_r.lower()


def region_matches(stored_region: str | None, tenant_region: str, current_region: str) -> bool:
    """True if stored report/run is visible: stored region matches tenant preference and current deployment."""
    if not current_region:
        return True
    stored = (stored_region or "").strip()
    if not stored:
        return True
    if tenant_region and stored.lower() != tenant_region.lower():
        return False
    return stored.lower() == current_region.lower()
