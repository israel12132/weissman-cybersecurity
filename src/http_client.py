"""
Weissman-cybersecurity: Enterprise HTTP client — fail-fast timeouts (5–8s),
exponential backoff on 429/5xx, and optional proxy rotation (PROXIES_LIST) for stealth.
"""
from __future__ import annotations

import logging
from typing import Any, Callable

import requests

try:
    from src.proxy_rotation import get_proxies_dict
except ImportError:
    def get_proxies_dict():
        return None
from tenacity import (
    retry,
    retry_if_exception,
    stop_after_attempt,
    wait_exponential,
    wait_random,
)

logger = logging.getLogger(__name__)

# Enterprise: strict 5–8s max; no 25–30s hangs
ENTERPRISE_HTTP_TIMEOUT = 6
ENTERPRISE_HTTP_TIMEOUT_MAX = 8


def _should_retry(e: BaseException) -> bool:
    """Retry on rate limit (429), server errors (5xx), and transport failures."""
    if isinstance(e, requests.exceptions.HTTPError):
        if e.response is None:
            return True
        sc = e.response.status_code
        return sc == 429 or (500 <= sc < 600)
    if isinstance(e, (requests.exceptions.Timeout, requests.exceptions.ConnectionError)):
        return True
    return False


def _backoff_with_jitter() -> Callable:
    """Exponential 2s, 4s, 8s with random jitter (0–1s) to mimic human intervals."""
    return wait_exponential(multiplier=1, min=2, max=8) + wait_random(0, 1)


@retry(
    stop=stop_after_attempt(3),
    wait=_backoff_with_jitter(),
    retry=retry_if_exception(_should_retry),
    reraise=True,
    before_sleep=lambda retry_state: logger.debug(
        "HTTP retry %s for %s", retry_state.attempt_number, getattr(retry_state.outcome, "exception", None)
    ),
)
def safe_get(
    url: str,
    timeout: int = ENTERPRISE_HTTP_TIMEOUT,
    **kwargs: Any,
) -> requests.Response:
    """GET with enterprise timeout and retry on 429/5xx/timeout. Uses proxy rotation if PROXIES_LIST set."""
    timeout = min(max(timeout, 1), ENTERPRISE_HTTP_TIMEOUT_MAX)
    try:
        proxies = get_proxies_dict()
    except Exception:
        proxies = None
    if proxies and "proxies" not in kwargs:
        kwargs["proxies"] = proxies
    r = requests.get(url, timeout=timeout, **kwargs)
    r.raise_for_status()
    return r


@retry(
    stop=stop_after_attempt(3),
    wait=_backoff_with_jitter(),
    retry=retry_if_exception(_should_retry),
    reraise=True,
)
def safe_post(
    url: str,
    timeout: int = ENTERPRISE_HTTP_TIMEOUT,
    **kwargs: Any,
) -> requests.Response:
    """POST with enterprise timeout and retry on 429/5xx/timeout. Uses proxy rotation if set."""
    timeout = min(max(timeout, 1), ENTERPRISE_HTTP_TIMEOUT_MAX)
    try:
        proxies = get_proxies_dict()
    except Exception:
        proxies = None
    if proxies and "proxies" not in kwargs:
        kwargs["proxies"] = proxies
    r = requests.post(url, timeout=timeout, **kwargs)
    r.raise_for_status()
    return r


def get_with_retry(
    session: requests.Session,
    url: str,
    timeout: int = ENTERPRISE_HTTP_TIMEOUT,
    **kwargs: Any,
) -> requests.Response:
    """Session GET with enterprise timeout and retry on 429/5xx/timeout."""
    timeout = min(max(timeout, 1), ENTERPRISE_HTTP_TIMEOUT_MAX)

    @retry(
        stop=stop_after_attempt(3),
        wait=_backoff_with_jitter(),
        retry=retry_if_exception(_should_retry),
        reraise=True,
    )
    def _do() -> requests.Response:
        req_kw = dict(kwargs)
        try:
            proxies = get_proxies_dict()
        except Exception:
            proxies = None
        if proxies and "proxies" not in req_kw:
            req_kw["proxies"] = proxies
        r = session.get(url, timeout=timeout, **req_kw)
        r.raise_for_status()
        return r

    return _do()


def post_with_retry(
    session: requests.Session,
    url: str,
    timeout: int = ENTERPRISE_HTTP_TIMEOUT,
    **kwargs: Any,
) -> requests.Response:
    """Session POST with enterprise timeout and retry on 429/5xx/timeout."""
    timeout = min(max(timeout, 1), ENTERPRISE_HTTP_TIMEOUT_MAX)

    @retry(
        stop=stop_after_attempt(3),
        wait=_backoff_with_jitter(),
        retry=retry_if_exception(_should_retry),
        reraise=True,
    )
    def _do() -> requests.Response:
        req_kw = dict(kwargs)
        try:
            proxies = get_proxies_dict()
        except Exception:
            proxies = None
        if proxies and "proxies" not in req_kw:
            req_kw["proxies"] = proxies
        r = session.post(url, timeout=timeout, **req_kw)
        r.raise_for_status()
        return r

    return _do()
