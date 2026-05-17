"""Short-lived cache for external feed results (NVD, GitHub, OSV, OTX, HIBP)."""

from __future__ import annotations

import json
import logging
import os
import threading
import time
from dataclasses import asdict, is_dataclass
from typing import Any, Optional

logger = logging.getLogger("weissman.feed_cache")

# `FEED_CACHE_TTL_SECONDS` is the canonical key; keep `WEISSMAN_FEED_CACHE_TTL`
# as backward-compatible fallback for existing deployments.
_ttl_raw = os.environ.get("FEED_CACHE_TTL_SECONDS")
if _ttl_raw is None:
    _ttl_raw = os.environ.get("WEISSMAN_FEED_CACHE_TTL", "300")
FEED_CACHE_TTL_SECONDS: int = int(_ttl_raw)
REDIS_URL: Optional[str] = os.environ.get("REDIS_URL")
CACHE_KEY_PREFIX = "weissman:feed:"
_EMPTY_PAYLOAD = '{"empty_result":true}'

_redis_client: Optional[Any] = None
_redis_init_lock = threading.Lock()


def _get_redis():
    """Lazy-init Redis client; returns None if unavailable."""
    global _redis_client
    if _redis_client is not None:
        return _redis_client
    if not REDIS_URL:
        return None

    with _redis_init_lock:
        if _redis_client is not None:
            return _redis_client
        try:
            import redis

            _redis_client = redis.from_url(REDIS_URL, socket_timeout=2, decode_responses=True)
            _redis_client.ping()
            logger.debug("feed_cache: Redis backend active")
            return _redis_client
        except Exception as exc:
            logger.warning("feed_cache: Redis unavailable (%s) — using in-process cache", exc)
            _redis_client = None
            return None


# {cache_key: (expires_at_epoch, payload_json)}
_mem_cache: dict[str, tuple[float, str]] = {}
_mem_lock = threading.RLock()


def _serialise(findings: list[Any]) -> str:
    """Convert a list of findings (pydantic/dataclass/dicts) to JSON."""

    def _to_dict(item: Any):
        if hasattr(item, "model_dump"):
            return item.model_dump(mode="json")
        if is_dataclass(item) and not isinstance(item, type):
            return asdict(item)
        if hasattr(item, "__dict__"):
            return item.__dict__
        return item

    if not findings:
        return _EMPTY_PAYLOAD
    return json.dumps([_to_dict(f) for f in findings], default=str)


def _deserialise(raw: str) -> list[dict]:
    """Return plain dicts for cached feed items."""
    if raw == _EMPTY_PAYLOAD:
        return []
    decoded = json.loads(raw)
    if isinstance(decoded, list):
        return decoded
    return []


def get_cached_feed(cache_key: str) -> Optional[list[dict]]:
    """
    Return cached feed findings for *cache_key*, or None on cache miss.
    Returned objects are plain dict payloads.
    """
    full_key = CACHE_KEY_PREFIX + cache_key
    r = _get_redis()

    if r is not None:
        try:
            raw = r.get(full_key)
            if raw is not None:
                logger.debug("feed_cache HIT (redis): %s", cache_key)
                return _deserialise(raw)
        except Exception as exc:
            logger.warning("feed_cache: Redis GET error (%s) — bypassing cache", exc)
        return None

    with _mem_lock:
        entry = _mem_cache.get(full_key)
        if not entry:
            return None
        expires_at, raw = entry
        if time.monotonic() < expires_at:
            logger.debug("feed_cache HIT (mem): %s", cache_key)
            return _deserialise(raw)
        _mem_cache.pop(full_key, None)
        return None


def set_cached_feed(cache_key: str, findings: list[Any], *, cache_empty: bool = True) -> None:
    """
    Store *findings* under *cache_key* for FEED_CACHE_TTL_SECONDS.
    Silently swallows errors so cache failures never break scans.
    """
    if not findings and not cache_empty:
        return

    full_key = CACHE_KEY_PREFIX + cache_key
    try:
        raw = _serialise(findings)
    except Exception as exc:
        logger.warning("feed_cache: serialisation failed (%s) — not caching", exc)
        return

    r = _get_redis()
    if r is not None:
        try:
            r.setex(full_key, FEED_CACHE_TTL_SECONDS, raw)
            logger.debug(
                "feed_cache SET (redis): %s TTL=%ds len=%d",
                cache_key,
                FEED_CACHE_TTL_SECONDS,
                len(findings),
            )
        except Exception as exc:
            logger.warning("feed_cache: Redis SET error (%s)", exc)
        return

    expires_at = time.monotonic() + FEED_CACHE_TTL_SECONDS
    with _mem_lock:
        _mem_cache[full_key] = (expires_at, raw)
    logger.debug("feed_cache SET (mem): %s TTL=%ds len=%d", cache_key, FEED_CACHE_TTL_SECONDS, len(findings))


def invalidate_feed(cache_key: str) -> None:
    """Force-expire one cached feed entry."""
    full_key = CACHE_KEY_PREFIX + cache_key
    r = _get_redis()
    if r is not None:
        try:
            r.delete(full_key)
        except Exception:
            pass
    with _mem_lock:
        _mem_cache.pop(full_key, None)


def invalidate_all_feeds() -> None:
    """Flush all feed cache entries."""
    r = _get_redis()
    if r is not None:
        try:
            keys = list(r.scan_iter(match=CACHE_KEY_PREFIX + "*", count=200))
            if keys:
                r.delete(*keys)
        except Exception:
            pass

    with _mem_lock:
        keys_to_del = [k for k in _mem_cache if k.startswith(CACHE_KEY_PREFIX)]
        for k in keys_to_del:
            _mem_cache.pop(k, None)
