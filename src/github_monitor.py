"""
GitHub Live Stream Monitoring: Events API + exploit-like signatures.
Discovers new repos with CVE/RCE/PrivEsc/Zero-Day/shellcode; tracks high-value profiles.
No hardcoded limits; IP rotation enforced via http_client.
"""
from __future__ import annotations

import logging
import os
import re
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

GITHUB_EVENTS_API = "https://api.github.com/events"
GITHUB_USER_EVENTS_API = "https://api.github.com/users/{login}/events/public"
# Exploit-like signatures for repo name/description/topics
EXPLOIT_SIGNATURES = re.compile(
    r"\b(CVE-\d{4}-\d+|RCE|PrivEsc|Zero-?[Dd]ay|exploit|shellcode|payload|poc|0day|vuln)\b",
    re.I,
)
# High-value profiles: from env GITHUB_WATCH_PROFILES (comma-separated logins)
PER_PAGE = 30
REQUEST_TIMEOUT = min(ENTERPRISE_HTTP_TIMEOUT, 10)


def _github_session() -> requests.Session:
    s = requests.Session()
    s.headers["Accept"] = "application/vnd.github.v3+json"
    s.headers["X-GitHub-Api-Version"] = "2022-11-28"
    token = (os.getenv("GITHUB_TOKEN") or "").strip()
    if token:
        s.headers["Authorization"] = f"Bearer {token}"
    try:
        from src.proxy_rotation import get_proxies_dict
        proxies = get_proxies_dict()
        if proxies:
            s.proxies = proxies
    except Exception:
        pass
    return s


def _repo_has_exploit_signature(repo: dict[str, Any]) -> bool:
    """True if repo name, description, or topics match exploit-like patterns."""
    name = (repo.get("name") or "")
    desc = (repo.get("description") or "")
    topics = repo.get("topics") or []
    combined = " ".join([name, desc] + list(topics))
    return bool(EXPLOIT_SIGNATURES.search(combined))


def fetch_public_events(per_page: int = PER_PAGE) -> list[dict]:
    """Fetch recent public events from GitHub (no limit on count)."""
    out: list[dict] = []
    try:
        session = _github_session()
        r = get_with_retry(
            session,
            GITHUB_EVENTS_API,
            timeout=REQUEST_TIMEOUT,
            params={"per_page": min(per_page, 100)},
        )
        r.raise_for_status()
        data = r.json()
        if isinstance(data, list):
            out = data
    except Exception as e:
        logger.debug("GitHub events fetch: %s", e)
    return out


def filter_exploit_like_repos(events: list[dict]) -> list[dict]:
    """From events, return repo payloads that look exploit-related (no limit)."""
    repos: list[dict] = []
    seen: set[str] = set()
    for ev in events:
        repo = (ev.get("repo") or {})
        payload = ev.get("payload") or {}
        full_name = repo.get("full_name") or ""
        if not full_name or full_name in seen:
            continue
        # PushEvent: repo in ev.repo; CreateEvent: repo in payload
        r = repo
        if ev.get("type") == "CreateEvent":
            r = payload.get("repository") or repo
        if not r:
            continue
        if isinstance(r, dict) and _repo_has_exploit_signature(r):
            seen.add(full_name)
            repos.append({
                "full_name": full_name,
                "html_url": r.get("html_url") or f"https://github.com/{full_name}",
                "description": r.get("description") or "",
                "event_type": ev.get("type"),
                "actor": (ev.get("actor") or {}).get("login"),
            })
        # Also check repo from ev.repo (payload might have more detail)
        if repo.get("full_name") and repo.get("full_name") not in seen:
            if _repo_has_exploit_signature(repo):
                seen.add(repo["full_name"])
                repos.append({
                    "full_name": repo["full_name"],
                    "html_url": repo.get("html_url") or f"https://github.com/{repo['full_name']}",
                    "description": repo.get("description") or "",
                    "event_type": ev.get("type"),
                    "actor": (ev.get("actor") or {}).get("login"),
                })
    return repos


def get_watch_profiles() -> list[str]:
    """High-value developer logins from env (no limit)."""
    raw = (os.getenv("GITHUB_WATCH_PROFILES") or "").strip()
    if not raw:
        return []
    return [x.strip() for x in raw.split(",") if x.strip()]


def fetch_user_events(login: str) -> list[dict]:
    """Fetch public events for a user."""
    out: list[dict] = []
    try:
        session = _github_session()
        url = GITHUB_USER_EVENTS_API.format(login=login)
        r = get_with_retry(session, url, timeout=REQUEST_TIMEOUT, params={"per_page": 30})
        r.raise_for_status()
        data = r.json()
        if isinstance(data, list):
            out = data
    except Exception as e:
        logger.debug("GitHub user events %s: %s", login, e)
    return out


def run_github_events_scan() -> list[dict]:
    """
    One cycle: fetch public events, return exploit-like repo discoveries (no limit).
    Caller can publish to Command Center / Telegram.
    """
    events = fetch_public_events()
    return filter_exploit_like_repos(events)


def run_github_profile_watch() -> list[dict]:
    """
    For each GITHUB_WATCH_PROFILES user, fetch events and return new push/create activity
    that looks exploit-related. No limit on profiles or results.
    """
    results: list[dict] = []
    for login in get_watch_profiles():
        events = fetch_user_events(login)
        for repo_info in filter_exploit_like_repos(events):
            repo_info["watched_user"] = login
            results.append(repo_info)
    return results
