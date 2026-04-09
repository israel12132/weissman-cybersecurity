"""
Weissman-cybersecurity: Supply Chain Intelligence.
NPM, PyPI, RubyGems footprint; typosquatting detection; compromised dependency check (OSV).
"""
from __future__ import annotations

import json
import logging
import re
from dataclasses import dataclass, field
from typing import Any

import requests

from src.http_client import safe_get, safe_post, ENTERPRISE_HTTP_TIMEOUT

logger = logging.getLogger(__name__)

NPM_SEARCH = "https://registry.npmjs.org/-/v1/search"
NPM_REGISTRY = "https://registry.npmjs.org"
PYPI_SEARCH = "https://pypi.org/search/"
OSV_QUERY = "https://api.osv.dev/v1/query"


@dataclass
class PackageInfo:
    name: str
    ecosystem: str  # npm, pypi, rubygems
    version: str | None
    description: str | None
    typosquat_risk: bool = False
    vuln_count: int = 0
    extra: dict[str, Any] = field(default_factory=dict)


def _normalize(name: str) -> str:
    return re.sub(r"[-_.]", "", (name or "").lower())


def _typosquat_similar(a: str, b: str) -> bool:
    """Heuristic: names very similar (one char diff or common typos)."""
    an, bn = _normalize(a), _normalize(b)
    if an == bn:
        return False
    if abs(len(an) - len(bn)) > 2:
        return False
    # Levenshtein-like: allow one char diff
    if len(an) == len(bn):
        diffs = sum(1 for i in range(len(an)) if an[i] != bn[i])
        if diffs <= 1:
            return True
    # one extra/missing char
    if an in bn or bn in an:
        return True
    return False


def search_npm_packages(org_or_prefix: str, limit: int = 20) -> list[PackageInfo]:
    """Search NPM for packages matching org/scope or name prefix."""
    out: list[PackageInfo] = []
    try:
        r = safe_get(NPM_SEARCH, params={"text": org_or_prefix, "size": limit}, timeout=ENTERPRISE_HTTP_TIMEOUT)
        if r.status_code != 200:
            return []
        data = r.json()
        objects = data.get("objects") or []
        for item in objects[:limit]:
            if not isinstance(item, dict):
                continue
            pkg = item.get("package") or item
            if not isinstance(pkg, dict):
                continue
            name = pkg.get("name") or ""
            if not name:
                continue
            out.append(
                PackageInfo(
                    name=name,
                    ecosystem="npm",
                    version=(pkg.get("version") or "").strip() or None,
                    description=(pkg.get("description") or "").strip() or None,
                    typosquat_risk=False,
                    extra=pkg,
                )
            )
    except Exception as e:
        logger.warning("NPM search failed: %s", e)
    return out


def search_pypi_packages(org_or_prefix: str, limit: int = 20) -> list[PackageInfo]:
    """Search PyPI for packages matching name prefix (PyPI has no org scope)."""
    out: list[PackageInfo] = []
    try:
        r = safe_get("https://pypi.org/search/", params={"q": org_or_prefix}, timeout=ENTERPRISE_HTTP_TIMEOUT)
        if r.status_code != 200:
            return []
        r2 = safe_get(
            "https://pypi.org/pypi/{}/json".format(org_or_prefix.split()[0]),
            timeout=ENTERPRISE_HTTP_TIMEOUT,
        )
        if r2.status_code == 200:
            try:
                d = r2.json()
                info = d.get("info") or {}
                out.append(
                    PackageInfo(
                        name=info.get("name") or org_or_prefix,
                        ecosystem="pypi",
                        version=info.get("version"),
                        description=info.get("summary"),
                        extra=info,
                    )
                )
            except Exception:
                pass
        # Fallback: scrape search results (simplified - just one package name from query)
        if not out and org_or_prefix:
            out.append(
                PackageInfo(
                    name=org_or_prefix.strip().replace(" ", "-")[:64],
                    ecosystem="pypi",
                    version=None,
                    description=None,
                )
            )
    except Exception as e:
        logger.warning("PyPI search failed: %s", e)
    return out[:limit]


def check_osv_for_package(ecosystem: str, name: str) -> int:
    """Return count of known vulnerabilities for a package (OSV API)."""
    if not name or not ecosystem:
        return 0
    try:
        r = safe_post(
            OSV_QUERY,
            json={"package": {"name": name, "ecosystem": ecosystem}},
            timeout=ENTERPRISE_HTTP_TIMEOUT,
        )
        if r.status_code != 200:
            return 0
        data = r.json()
        vulns = data.get("vulns") or []
        return len(vulns)
    except Exception as e:
        logger.debug("OSV query failed: %s", e)
        return 0


def run_supply_chain_scan(
    org_name: str,
    domain: str | None = None,
    check_typosquat: bool = True,
    check_compromised: bool = True,
) -> list[PackageInfo]:
    """
    For a target org: discover NPM/PyPI footprint, flag typosquatting, and check OSV for vulns.
    domain: optional root domain (e.g. acme.com -> search acme).
    """
    results: list[PackageInfo] = []
    prefix = (org_name or "").strip()[:32]
    if domain and not prefix:
        prefix = domain.split(".")[0][:32]
    if not prefix:
        return results
    seen_names: set[str] = set()
    for pkg in search_npm_packages(prefix, limit=15):
        if pkg.name in seen_names:
            continue
        seen_names.add(pkg.name)
        if check_compromised:
            pkg.vuln_count = check_osv_for_package("npm", pkg.name)
        if check_typosquat and prefix:
            pkg.typosquat_risk = _typosquat_similar(pkg.name, prefix)
        results.append(pkg)
    for pkg in search_pypi_packages(prefix, limit=15):
        if pkg.name in seen_names:
            continue
        seen_names.add(pkg.name)
        if check_compromised:
            pkg.vuln_count = check_osv_for_package("PyPI", pkg.name)
        if check_typosquat and prefix:
            pkg.typosquat_risk = _typosquat_similar(pkg.name, prefix)
        results.append(pkg)
    return results
