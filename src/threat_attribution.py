"""
Weissman-cybersecurity: APT (Advanced Persistent Threat) Attribution.
Correlates Critical/High CVEs with known threat actors from public intel.
Used in PDF reports to provide "Likely Threat Actors" for client awareness.
"""
from __future__ import annotations

import logging
import re
from typing import Any

logger = logging.getLogger(__name__)

# Public intel: product/component keywords -> APT groups known to target them
PRODUCT_TO_APT: list[tuple[list[str], list[str]]] = [
    (["microsoft", "windows", "office", "exchange", "azure"], ["APT29", "Lazarus", "Fancy Bear"]),
    (["nginx", "apache", "openssl", "linux", "kernel"], ["Fancy Bear", "Lazarus", "Sandworm"]),
    (["vmware", "vsphere", "esxi"], ["Sandworm", "APT29"]),
    (["citrix", "adc", "netscaler"], ["APT29", "Fancy Bear"]),
    (["fortinet", "fortios", "vpn"], ["Sandworm", "APT28"]),
    (["jenkins", "gitlab", "jira", "confluence"], ["Lazarus", "APT38"]),
    (["wordpress", "drupal", "joomla"], ["Fancy Bear", "APT28"]),
    (["php", "java", "node", "python"], ["Lazarus", "APT29"]),
]

# Severity -> default actors when no product match
CRITICAL_DEFAULT_ACTORS = ["Lazarus", "Fancy Bear", "APT29"]
HIGH_DEFAULT_ACTORS = ["Fancy Bear", "APT28"]
MEDIUM_DEFAULT_ACTORS = ["APT28"]


def get_threat_actors_for_finding(
    cve_id: str = "",
    severity: str = "",
    title: str = "",
    affected_components: list[str] | None = None,
    description: str = "",
) -> list[str]:
    """
    Return likely threat actors (APT attribution) for a finding.
    Used when severity is Critical or High; included in PDF as "Likely Threat Actors".
    """
    severity = (severity or "medium").lower()
    components = list(affected_components or [])
    if isinstance(affected_components, str):
        components = [affected_components]
    text = " ".join([title or "", description or ""] + components).lower()
    actors_set: set[str] = set()

    for keywords, apt_list in PRODUCT_TO_APT:
        if any(kw in text for kw in keywords):
            actors_set.update(apt_list)

    if severity == "critical":
        actors_set.update(CRITICAL_DEFAULT_ACTORS)
    elif severity == "high":
        actors_set.update(HIGH_DEFAULT_ACTORS)
    elif severity == "medium":
        actors_set.update(MEDIUM_DEFAULT_ACTORS)

    # Return unique, ordered (by default lists first)
    result = []
    for name in CRITICAL_DEFAULT_ACTORS + HIGH_DEFAULT_ACTORS + MEDIUM_DEFAULT_ACTORS:
        if name in actors_set and name not in result:
            result.append(name)
    for a in sorted(actors_set):
        if a not in result:
            result.append(a)
    return result[:5]  # cap at 5


def get_threat_actors_for_findings(findings: list[dict[str, Any]]) -> list[str]:
    """
    Aggregate likely threat actors across all Critical/High findings in a report.
    Used for PDF "Likely Threat Actors" section.
    """
    all_actors: set[str] = set()
    for item in findings:
        f = item.get("finding") or {}
        sev = (f.get("severity") or "").lower()
        if sev not in ("critical", "high"):
            continue
        actors = get_threat_actors_for_finding(
            cve_id=f.get("id") or f.get("source_id") or "",
            severity=sev,
            title=f.get("title") or "",
            affected_components=f.get("affected_components") or [],
            description=f.get("description") or "",
        )
        all_actors.update(actors)
    return sorted(all_actors)
