"""
Weissman-cybersecurity: Stealth & IP rotation for Fortune 500 scanning.
Reads PROXIES_LIST (comma-separated) or PROXIES_FILE (path to file, one proxy per line)
and rotates proxy per request to avoid WAF/Cloudflare bans.
"""
from __future__ import annotations

import logging
import os
import random
from pathlib import Path

logger = logging.getLogger(__name__)

_PROXIES_CACHE: list[str] | None = None


def _load_proxies() -> list[str]:
    """Load proxy list from PROXIES_LIST env or PROXIES_FILE. Cached."""
    global _PROXIES_CACHE
    if _PROXIES_CACHE is not None:
        return _PROXIES_CACHE
    out: list[str] = []
    raw = (os.getenv("PROXIES_LIST") or "").strip()
    if raw:
        out = [p.strip() for p in raw.split(",") if p.strip()]
    if not out:
        path = (os.getenv("PROXIES_FILE") or "").strip()
        if path and Path(path).exists():
            try:
                out = [
                    line.strip()
                    for line in Path(path).read_text().splitlines()
                    if line.strip() and not line.strip().startswith("#")
                ]
            except Exception as e:
                logger.warning("PROXIES_FILE read failed: %s", e)
    _PROXIES_CACHE = out
    return out


def get_random_proxy() -> str | None:
    """Return a random proxy URL from the list, or None if none configured."""
    proxies = _load_proxies()
    if not proxies:
        return None
    return random.choice(proxies)


def get_proxies_dict() -> dict[str, str] | None:
    """
    Return requests-style proxies dict for use with requests/httpx.
    e.g. {"http": "http://proxy:8080", "https": "http://proxy:8080"}.
    Returns None if no proxies configured.
    """
    url = get_random_proxy()
    if not url:
        return None
    return {"http": url, "https": url}


def session_with_proxy(session):
    """Set a random proxy on the session if PROXIES_LIST/PROXIES_FILE is set."""
    d = get_proxies_dict()
    if d:
        session.proxies.update(d)
    return session
