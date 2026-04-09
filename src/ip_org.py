"""
Weissman-cybersecurity: IP-to-Organization mapping via BGP/ASN.
Identifies IP ownership for target corporation (e.g. for scope validation).
"""
from __future__ import annotations

import logging
import re
from typing import Any

import requests

from src.http_client import safe_get, ENTERPRISE_HTTP_TIMEOUT

logger = logging.getLogger(__name__)

# RIPE Stat API (no key required) for IP whois / ASN
RIPE_WHOIS = "https://stat.ripe.net/data/whois/data.json"
IPINFO_ASN = "https://ipinfo.io/{ip}/json"


def _is_valid_ip(ip: str) -> bool:
    if not ip or not ip.strip():
        return False
    ip = ip.strip()
    # IPv4
    if re.match(r"^(\d{1,3}\.){3}\d{1,3}$", ip):
        parts = [int(x) for x in ip.split(".") if x.isdigit()]
        return len(parts) == 4 and all(0 <= p <= 255 for p in parts)
    # IPv6 (simple)
    if ":" in ip and re.match(r"^[\da-fA-F:.]{3,45}$", ip):
        return True
    return False


def get_asn_org_ripe(ip: str, timeout: int = ENTERPRISE_HTTP_TIMEOUT) -> dict[str, Any] | None:
    """Resolve ASN and org via RIPE Stat. Returns dict with asn, org, netname, country."""
    if not _is_valid_ip(ip):
        return None
    try:
        r = safe_get(RIPE_WHOIS, params={"resource": ip.strip()}, timeout=min(timeout, 8))
        if r.status_code != 200:
            return None
        data = r.json()
        records = (data.get("data") or {}).get("records") or []
        out: dict[str, Any] = {"asn": None, "org": None, "netname": None, "country": None}
        for rec in records:
            key = (rec.get("key") or "").strip().lower()
            value = (rec.get("value") or "").strip()
            if key == "origin":
                out["asn"] = value
            elif key == "org-name" or key == "descr":
                if not out["org"] or key == "org-name":
                    out["org"] = value
            elif key == "netname":
                out["netname"] = value
            elif key == "country":
                out["country"] = value
        return out if out["asn"] or out["org"] else None
    except Exception as e:
        logger.debug("RIPE whois failed for %s: %s", ip, e)
        return None


def get_asn_org_ipinfo(ip: str, timeout: int = ENTERPRISE_HTTP_TIMEOUT) -> dict[str, Any] | None:
    """Resolve ASN/org via ipinfo.io (free tier). Returns dict with asn, org, country."""
    if not _is_valid_ip(ip):
        return None
    try:
        url = IPINFO_ASN.format(ip=ip.strip())
        r = safe_get(url, timeout=min(timeout, 8))
        if r.status_code != 200:
            return None
        data = r.json()
        org = data.get("org") or ""
        # org often "AS12345 Org Name"
        asn = None
        if org.startswith("AS"):
            parts = org.split(None, 1)
            asn = parts[0] if parts else None
            org = parts[1] if len(parts) > 1 else org
        return {
            "asn": asn or data.get("asn"),
            "org": org or data.get("org"),
            "country": data.get("country"),
            "netname": None,
        }
    except Exception as e:
        logger.debug("ipinfo failed for %s: %s", ip, e)
        return None


def get_ip_org(ip: str, prefer_ripe: bool = True) -> dict[str, Any] | None:
    """
    Identify organization and ASN for an IP. Tries RIPE then ipinfo.
    Returns dict: asn, org, netname, country.
    """
    if prefer_ripe:
        info = get_asn_org_ripe(ip)
        if info:
            return info
        return get_asn_org_ipinfo(ip)
    info = get_asn_org_ipinfo(ip)
    if info:
        return info
    return get_asn_org_ripe(ip)


def ip_belongs_to_org(ip: str, org_keywords: list[str]) -> bool:
    """
    Heuristic: True if the IP's resolved org name contains any of the given keywords.
    org_keywords: e.g. ["Google", "Amazon", "Acme Corp"].
    """
    info = get_ip_org(ip)
    if not info:
        return False
    org = (info.get("org") or "").lower()
    netname = (info.get("netname") or "").lower()
    for kw in (org_keywords or []):
        if kw and kw.lower() in (org + " " + netname):
            return True
    return False
