"""
Weissman-cybersecurity Enterprise: CVSS 3.1 vector and EPSS (Exploit Prediction Scoring).
"""
import logging
from typing import Any

import requests

from src.http_client import safe_get, ENTERPRISE_HTTP_TIMEOUT

logger = logging.getLogger(__name__)

EPSS_API = "https://api.first.org/data/v1/epss"


def severity_to_cvss_vector(severity: str) -> str:
    """
    Map severity to a minimal CVSS 3.1 vector string.
    Format: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:X/I:X/A:X
    """
    s = (severity or "medium").lower()
    if s == "critical":
        return "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
    if s == "high":
        return "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"
    if s == "medium":
        return "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:L/A:N"
    if s == "low":
        return "CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:N/I:L/A:N"
    return "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N"


def get_epss_score(cve_id: str) -> float | None:
    """Fetch EPSS (0-1) for CVE from API. Returns None on failure."""
    if not cve_id or not cve_id.strip().upper().startswith("CVE-"):
        return None
    try:
        r = safe_get(EPSS_API, params={"cve": cve_id.strip()}, timeout=ENTERPRISE_HTTP_TIMEOUT)
        if r.status_code != 200:
            return None
        data = r.json()
        for item in (data.get("data") or [])[:1]:
            return float(item.get("epss", 0) or 0)
        return None
    except Exception as e:
        logger.debug("EPSS fetch failed for %s: %s", cve_id, e)
        return None


def cvss_severity_to_numeric(severity: str) -> float:
    """Map severity to numeric (0-10) for scoring. Critical=10, High=8.5, Medium=5, Low=2."""
    s = (severity or "medium").lower()
    return {"critical": 10.0, "high": 8.5, "medium": 5.0, "low": 2.0}.get(s, 5.0)


def weissman_priority_score(
    cvss_value: float | None = None,
    severity: str | None = None,
    epss_value: float | None = None,
    asset_criticality: float = 1.0,
) -> float:
    """
    Weissman Priority Score: CVSS * EPSS * Asset_Criticality.
    Weights exploit probability (EPSS) and asset importance. Range typically 0–100 (scale 0-10 * 0-1 * 0-2).
    asset_criticality: 0.5 (low), 1.0 (normal), 1.5 (critical asset). Result scaled to 0-100.
    """
    cvss = cvss_value
    if cvss is None and severity:
        cvss = cvss_severity_to_numeric(severity)
    if cvss is None:
        cvss = 5.0
    epss = epss_value if epss_value is not None else 0.1
    epss = max(0.0, min(1.0, float(epss)))
    criticality = max(0.5, min(2.0, float(asset_criticality)))
    raw = cvss * epss * criticality
    return round(min(100.0, raw * 5.0), 2)  # scale to 0-100
