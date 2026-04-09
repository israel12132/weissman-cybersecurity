"""
Weissman-cybersecurity: Secret leak monitoring (GitHub/GitLab).
Scans public repos for leaked API keys, .env, hardcoded credentials for target org.
"""
from __future__ import annotations

import logging
import os
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any

try:
    from dotenv import load_dotenv
    load_dotenv(Path(__file__).resolve().parent.parent / ".env")
except Exception:
    pass

import requests

from src.http_client import get_with_retry, ENTERPRISE_HTTP_TIMEOUT

logger = logging.getLogger(__name__)

GITHUB_API = "https://api.github.com"
GITHUB_SEARCH_CODE = "https://api.github.com/search/code"


@dataclass
class PotentialLeak:
    repo: str
    path: str
    url: str
    snippet: str
    pattern: str  # e.g. api_key, .env, password
    severity: str  # high, medium, low


def _get_github_token() -> str:
    return (os.getenv("GITHUB_TOKEN") or "").strip()


# Patterns that indicate possible secrets (for snippet highlighting).
SECRET_PATTERNS = [
    (r"api[_-]?key\s*[:=]\s*['\"]?[a-zA-Z0-9_\-]{20,}", "api_key"),
    (r"password\s*[:=]\s*['\"][^'\"]+['\"]", "password"),
    (r"secret\s*[:=]\s*['\"]?[a-zA-Z0-9_\-]{16,}", "secret"),
    (r"\.env", ".env"),
    (r"aws_secret_access_key|AKIA[0-9A-Z]{16}", "aws_secret"),
    (r"ghp_[a-zA-Z0-9]{36}", "github_token"),
]


# Enterprise: 150 results for massive-org credential leak detection (Fortune 500)
SECRET_SCAN_MAX_RESULTS_DEFAULT = 150


def search_github_code(
    org_or_query: str,
    token: str | None = None,
    max_results: int = SECRET_SCAN_MAX_RESULTS_DEFAULT,
) -> list[PotentialLeak]:
    """
    Search GitHub code for org name + sensitive patterns. Enterprise default 150 results.
    Uses GitHub Code Search API: "org:ORG api_key" or "ORG .env".
    """
    token = token or _get_github_token()
    headers = {"Accept": "application/vnd.github.v3+json"}
    if token:
        headers["Authorization"] = f"token {token}"
    results: list[PotentialLeak] = []
    org = (org_or_query or "").strip()
    if not org:
        return results
    queries = [
        f'"{org}" "api_key"',
        f'"{org}" ".env"',
        f'"{org}" "password"',
        f'org:{org} "api_key"',
    ]
    seen: set[tuple[str, str]] = set()
    session = requests.Session()
    if headers:
        session.headers.update(headers)
    for q in queries[:3]:
        try:
            r = get_with_retry(
                session,
                GITHUB_SEARCH_CODE,
                params={"q": q, "per_page": min(50, max_results)},
                timeout=ENTERPRISE_HTTP_TIMEOUT,
            )
            if r.status_code != 200:
                if r.status_code == 403:
                    logger.warning("GitHub rate limit or forbidden")
                break
            data = r.json()
            for item in (data.get("items") or [])[:50]:
                repo = (item.get("repository") or {}).get("full_name") or ""
                path = item.get("path") or ""
                html_url = item.get("html_url") or ""
                if (repo, path) in seen:
                    continue
                seen.add((repo, path))
                snippet = (item.get("text_matches") or [{}])[0].get("fragment") if item.get("text_matches") else ""
                if not snippet:
                    snippet = path
                results.append(
                    PotentialLeak(
                        repo=repo,
                        path=path,
                        url=html_url,
                        snippet=snippet[:500],
                        pattern="code_match",
                        severity="high" if ".env" in path or "config" in path.lower() else "medium",
                    )
                )
        except Exception as e:
            logger.warning("GitHub code search failed: %s", e)
    return results[:max_results]


def run_secret_scan(org_name: str, token: str | None = None) -> list[PotentialLeak]:
    """Entry: scan for potential credential leaks related to org."""
    return search_github_code(org_name, token=token)
