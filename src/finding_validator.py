"""
Verified-only reporting: run non-destructive PoC (safe_probe) per finding.
Only findings that pass validation are included in the PDF/Dashboard.
"""
import json
import logging
from typing import Any

from src.fingerprint import run_safe_probe
from src.models import ClientFinding

logger = logging.getLogger(__name__)


def _first_url_for_client(client_id: str, db_clients: list[dict]) -> str | None:
    """Get first scope domain as URL for a client."""
    for c in db_clients:
        if str(c.get("id")) != str(client_id):
            continue
        scope = c.get("scope") or {}
        if isinstance(scope, str):
            try:
                scope = json.loads(scope)
            except Exception:
                return None
        domains = scope.get("domains") or []
        for d in domains:
            d = (d or "").strip()
            if not d or str(d).startswith("*"):
                continue
            if d.startswith("http://") or d.startswith("https://"):
                return d
            return f"https://{d}"
    return None


def _tech_hint_for_finding(finding: Any) -> str:
    """First affected component for probe context."""
    comps = getattr(finding, "affected_components", None) or []
    if comps and len(comps) > 0 and comps[0]:
        return str(comps[0]).strip()
    return ""


def validate_findings(
    client_findings: list[ClientFinding],
    db_clients: list[dict],
    *,
    validate_critical_high_only: bool = False,
) -> list[ClientFinding]:
    """
    Run non-destructive PoC (safe_probe) per finding. Only return findings
    where the probe succeeded (target reachable, response received).
    If validate_critical_high_only is True, only run validation for Critical/High;
    others are included without validation (e.g. for low/medium we skip probe).
    """
    validated: list[ClientFinding] = []
    for cf in client_findings:
        url = _first_url_for_client(cf.client_id, db_clients)
        if not url:
            logger.debug("No URL for client %s, skipping validation for finding %s", cf.client_id, cf.finding.id)
            continue
        if validate_critical_high_only and (cf.finding.severity.value not in ("critical", "high")):
            validated.append(cf)
            continue
        tech = _tech_hint_for_finding(cf.finding)
        result = run_safe_probe(url, tech)
        if result is not None:
            validated.append(cf)
        else:
            logger.debug("Validation failed (probe returned None) for %s @ %s", cf.finding.id, url)
    return validated
