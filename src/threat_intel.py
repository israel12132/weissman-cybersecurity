"""
Exploit Intelligence: monitor GitHub for repos containing exploit/PoC/payload
keywords combined with tech stack names. Includes legacy repos (no date filter)
so 2010–2020 "ghost" targets remain in scope.
Phase 3: GITHUB_TOKEN missing → log warning, fallback to unauthenticated (or skip with status).
"""
import logging
import os
import re
import time
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
from src.models import ALLOWED_SHORT_TECH, normalize_tech_stack_to_list

logger = logging.getLogger(__name__)


EXPLOIT_KEYWORDS = ("exploit", "poc", "payload", "cve", "vuln")
GITHUB_SEARCH_URL = "https://api.github.com/search/repositories"
# No created: or pushed: filter – we want legacy (2010–2020) repos too.
PER_PAGE = 30
MAX_PAGES = 2
RATE_DELAY_SEC = 1.2


@dataclass
class ExploitRepo:
    full_name: str
    html_url: str
    description: str
    topics: list[str]
    created_at: str
    updated_at: str
    tech_mentions: list[str]  # parsed from name/description/topics
    raw: dict[str, Any]


def _session(token: str | None = None) -> requests.Session:
    s = requests.Session()
    s.headers["Accept"] = "application/vnd.github.v3+json"
    s.headers["X-GitHub-Api-Version"] = "2022-11-28"
    if token:
        s.headers["Authorization"] = f"Bearer {token}"
    return s


def _extract_tech_mentions(name: str, description: str, topics: list[str]) -> list[str]:
    """Normalize and dedupe tech-like tokens. Min 3 chars or in ALLOWED_SHORT_TECH (no 'in','act')."""
    combined = " ".join([name or "", description or ""] + list(topics or [])).lower()
    words = re.findall(r"\b[a-z0-9][a-z0-9._-]*", combined)
    tech_candidates = [
        w for w in words
        if (len(w) >= 3 or w in ALLOWED_SHORT_TECH)
        and w not in ("exploit", "poc", "payload", "cve", "vuln", "the", "for", "and", "with")
    ]
    return list(dict.fromkeys(tech_candidates))


def search_repos(
    tech_terms: list[str] | str,
    token: str | None = None,
    keywords: tuple[str, ...] = EXPLOIT_KEYWORDS,
) -> list[ExploitRepo]:
    """
    Search GitHub for repositories that contain any of `keywords` and any of `tech_terms`
    in name, description, or readme. tech_terms must be List[str]; comma string is split.
    Short/garbage terms (< 3 chars except allowed) are filtered.
    """
    tech_terms = normalize_tech_stack_to_list(tech_terms if isinstance(tech_terms, list) else (tech_terms or ""))
    if not tech_terms:
        return []
    session = _session(token)
    seen: set[str] = set()
    results: list[ExploitRepo] = []
    # One query per keyword + tech (no hard cap on combos; rate-limited by API).
    for kw in keywords:
        for tech in tech_terms:
            q = f"{kw} {tech} in:name,description,readme"
            params = {"q": q, "sort": "updated", "order": "desc", "per_page": PER_PAGE}
            try:
                r = get_with_retry(session, GITHUB_SEARCH_URL, params=params, timeout=ENTERPRISE_HTTP_TIMEOUT)
                if r.status_code == 403:
                    time.sleep(60)
                    continue
                r.raise_for_status()
                data = r.json()
                for item in data.get("items", []):
                    full_name = item.get("full_name", "")
                    if full_name in seen:
                        continue
                    seen.add(full_name)
                    name = item.get("name", "")
                    desc = item.get("description") or ""
                    topics = item.get("topics") or []
                    tech_mentions = _extract_tech_mentions(name, desc, topics)
                    results.append(
                        ExploitRepo(
                            full_name=full_name,
                            html_url=item.get("html_url", ""),
                            description=desc,
                            topics=topics,
                            created_at=item.get("created_at", ""),
                            updated_at=item.get("updated_at", ""),
                            tech_mentions=tech_mentions,
                            raw=item,
                        )
                    )
                time.sleep(RATE_DELAY_SEC)
            except Exception:
                continue
    return results


def _token_or_fallback():
    """Return GITHUB_TOKEN or None; log clear warning if missing (Phase 3: no silent fail)."""
    token = (os.getenv("GITHUB_TOKEN") or "").strip()
    if not token:
        logger.warning(
            "GITHUB_TOKEN missing: GitHub API will use unauthenticated rate limits (60/h). "
            "Set GITHUB_TOKEN in .env for higher limits. Proceeding with fallback."
        )
    return token or None


def fetch_exploit_repos_for_tech_stack(
    tech_stack: list[str] | str,
    token: str | None = None,
) -> list[ExploitRepo]:
    """
    Entry point: given tech stack (list or comma-separated string), return GitHub exploit repos.
    Strict List[str]; short/garbage terms filtered.
    """
    tech_list = normalize_tech_stack_to_list(tech_stack)
    token = token or _token_or_fallback()
    return search_repos(tech_list, token=token)


# Global monitoring: fetch ALL new exploit/PoC repos regardless of client (no tech filter in query).
GLOBAL_EXPLOIT_QUERIES = (
    "exploit in:name,description",
    "poc in:name,description",
    "zero day in:name,description",
    "vuln in:name,description",
)
GLOBAL_PER_PAGE = 50
GLOBAL_MAX_PAGES = 4


def search_global_exploit_repos(
    token: str | None = None,
    max_results: int = 200,
) -> list[ExploitRepo]:
    """
    Monitor ALL new exploit/PoC tools globally (no client name or tech filter).
    Used for cross-referencing: match returned repos against each client's tech stack
    and trigger CRITICAL alert when a global threat applies to that client.
    """
    token = token or _token_or_fallback()
    session = _session(token)
    seen: set[str] = set()
    results: list[ExploitRepo] = []
    for q in GLOBAL_EXPLOIT_QUERIES:
        if len(results) >= max_results:
            break
        for page in range(1, GLOBAL_MAX_PAGES + 1):
            if len(results) >= max_results:
                break
            params = {
                "q": q,
                "sort": "updated",
                "order": "desc",
                "per_page": min(GLOBAL_PER_PAGE, max_results - len(results)),
                "page": page,
            }
            try:
                r = get_with_retry(session, GITHUB_SEARCH_URL, params=params, timeout=ENTERPRISE_HTTP_TIMEOUT)
                if r.status_code == 403:
                    time.sleep(60)
                    continue
                r.raise_for_status()
                data = r.json()
                for item in data.get("items", []):
                    full_name = item.get("full_name", "")
                    if full_name in seen:
                        continue
                    seen.add(full_name)
                    name = item.get("name", "")
                    desc = item.get("description") or ""
                    topics = item.get("topics") or []
                    tech_mentions = _extract_tech_mentions(name, desc, topics)
                    results.append(
                        ExploitRepo(
                            full_name=full_name,
                            html_url=item.get("html_url", ""),
                            description=desc,
                            topics=topics,
                            created_at=item.get("created_at", ""),
                            updated_at=item.get("updated_at", ""),
                            tech_mentions=tech_mentions,
                            raw=item,
                        )
                    )
                time.sleep(RATE_DELAY_SEC)
            except Exception:
                continue
    return results


def get_global_threat_intel_for_pdf(tech_stack: list[str] | str, token: str | None = None, max_repos: int = 150) -> list[dict[str, Any]]:
    """
    For PDF "Preemptive Global Threat Intelligence" section: fetch global exploit repos,
    match to client tech stack, return list of {title, url, matched_tech, description}.
    Description is contextual: explains exactly how the tool can be used against the client's stack.
    """
    from src.exploit_matcher import filter_matching_exploits
    token = token or _token_or_fallback()
    repos = search_global_exploit_repos(token=token, max_results=max_repos)
    stack_list = normalize_tech_stack_to_list(tech_stack if isinstance(tech_stack, list) else (tech_stack or ""))
    matches = filter_matching_exploits(repos, stack_list)
    out: list[dict[str, Any]] = []
    for m in matches:
        r = m.exploit_repo
        matched = m.matched_tech[:5]
        tech_list = ", ".join(matched) if matched else "your stack"
        repo_desc = (r.description or "").strip()[:200]
        if repo_desc:
            description = (
                f"This tool exploits or targets the specific technologies detected in your environment ({tech_list}). "
                f"{repo_desc} "
                f"Verify compatibility with your deployed versions; use only in authorized testing."
            )
        else:
            description = (
                f"This tool can be used against the following components in your stack: {tech_list}. "
                f"Run only in authorized scope to validate whether your versions are affected."
            )
        out.append({
            "title": (r.full_name or r.raw.get("name", "Unknown"))[:120],
            "url": r.html_url or ("https://github.com/" + (r.full_name or "")),
            "matched_tech": matched,
            "description": description[:400],
        })
    return out
