"""
src/rate_limiter.py
===================
Per-tenant / per-IP rate limiting for expensive endpoints
(scan trigger, deep-fuzz, command-center scan).

Compatible with:
  - REDIS_URL env var (same as celery_app.py)
  - FastAPI dependency injection pattern used in app.py
  - get_tenant_id (src/web/tenant.py)
  - log_action (src/audit.py)

Usage in app.py:
    from src.rate_limiter import RateLimiter

    _scan_limiter = RateLimiter(
        key_prefix="scan_trigger",
        max_calls=5,         # 5 triggers …
        window_seconds=60,   # … per 60 seconds per tenant
    )

    @app.post("/api/scan/run-all")
    async def run_all(
        request: Request,
        tenant_id: str = Depends(get_tenant_id),
    ):
        _scan_limiter.check(tenant_id or _client_ip(request))
        ...

    @app.post("/api/command-center/scan")
    async def command_center_scan(
        body: ScanRequest,
        request: Request,
        db: Session = Depends(get_db),
        tenant_id: str = Depends(get_tenant_id),
    ):
        _cc_scan_limiter.check(tenant_id or _client_ip(request))
        ...
"""

import logging
import os
import time
from collections import defaultdict
from threading import Lock
from typing import Any, Optional

from fastapi import HTTPException

logger = logging.getLogger("weissman.rate_limiter")

REDIS_URL: Optional[str] = os.environ.get("REDIS_URL")


# ---------------------------------------------------------------------------
# Redis client (shared, lazy)
# ---------------------------------------------------------------------------
_redis_client: Optional[Any] = None
_redis_lock = Lock()


def _get_redis() -> Optional[Any]:
    global _redis_client
    if _redis_client is not None:
        return _redis_client
    if not REDIS_URL:
        return None
    with _redis_lock:
        if _redis_client is not None:
            return _redis_client
        try:
            import redis
            r = redis.from_url(REDIS_URL, socket_timeout=2, decode_responses=True)
            r.ping()
            _redis_client = r
            logger.debug("rate_limiter: Redis backend active")
            return _redis_client
        except Exception as exc:
            logger.warning("rate_limiter: Redis unavailable (%s) — falling back to in-process", exc)
            return None


# ---------------------------------------------------------------------------
# In-process fallback: sliding window per key
# { full_key: [timestamp, timestamp, ...] }
# ---------------------------------------------------------------------------
_mem_windows: dict[str, list[float]] = defaultdict(list)
_mem_lock = Lock()


# ---------------------------------------------------------------------------
# RateLimiter class
# ---------------------------------------------------------------------------

class RateLimiter:
    """
    Sliding-window rate limiter.

    Parameters
    ----------
    key_prefix      Logical name for the endpoint (e.g. "scan_trigger").
    max_calls       Maximum number of calls allowed within *window_seconds*.
    window_seconds  Length of the sliding time window in seconds.
    """

    def __init__(self, key_prefix: str, max_calls: int, window_seconds: int):
        self.key_prefix = key_prefix
        self.max_calls = max_calls
        self.window_seconds = window_seconds

    def _redis_key(self, identity: str) -> str:
        """Key format: weissman:rl:<prefix>:<identity>"""
        return f"weissman:rl:{self.key_prefix}:{identity}"

    def check(self, identity: str) -> None:
        """
        Check if *identity* (tenant_id or IP) is within rate limit.

        Raises HTTPException(429) if rate limit exceeded.
        Logs rate limit violations via logger.warning.

        Parameters
        ----------
        identity : str
            Unique identifier for the caller (tenant_id, IP address, or user_id)

        Raises
        ------
        HTTPException
            With status_code=429 if rate limit is exceeded
        """
        r = _get_redis()

        if r is not None:
            self._check_redis(r, identity)
        else:
            self._check_memory(identity)

    def _check_redis(self, r: Any, identity: str) -> None:
        """Redis-based rate limiting using sorted sets for sliding window."""
        key = self._redis_key(identity)
        now = time.time()
        window_start = now - self.window_seconds

        try:
            # Use Redis pipeline for atomic operations
            pipe = r.pipeline()

            # Remove expired entries from sorted set
            pipe.zremrangebyscore(key, 0, window_start)

            # Count current entries in window
            pipe.zcard(key)

            # Add current timestamp
            pipe.zadd(key, {str(now): now})

            # Set expiration on the key
            pipe.expire(key, self.window_seconds + 10)

            results = pipe.execute()
            count_before_add = results[1]

            if count_before_add >= self.max_calls:
                logger.warning(
                    "rate_limiter: %s exceeded limit for %s (%d/%d calls in %ds)",
                    identity,
                    self.key_prefix,
                    count_before_add,
                    self.max_calls,
                    self.window_seconds,
                )
                raise HTTPException(
                    status_code=429,
                    detail=f"Rate limit exceeded: {self.max_calls} calls per {self.window_seconds}s"
                )

            logger.debug(
                "rate_limiter: %s allowed for %s (%d/%d calls)",
                identity,
                self.key_prefix,
                count_before_add + 1,
                self.max_calls,
            )

        except HTTPException:
            # Re-raise rate limit exceptions
            raise
        except Exception as exc:
            # Redis error - fall back to memory check
            logger.warning("rate_limiter: Redis error (%s) — falling back to memory", exc)
            self._check_memory(identity)

    def _check_memory(self, identity: str) -> None:
        """In-memory rate limiting using sliding window of timestamps."""
        key = self._redis_key(identity)
        now = time.monotonic()
        window_start = now - self.window_seconds

        with _mem_lock:
            # Get or create window for this key
            timestamps = _mem_windows[key]

            # Remove expired timestamps (outside window)
            timestamps[:] = [ts for ts in timestamps if ts > window_start]

            # Check if limit exceeded
            if len(timestamps) >= self.max_calls:
                logger.warning(
                    "rate_limiter: %s exceeded limit for %s (%d/%d calls in %ds)",
                    identity,
                    self.key_prefix,
                    len(timestamps),
                    self.max_calls,
                    self.window_seconds,
                )
                raise HTTPException(
                    status_code=429,
                    detail=f"Rate limit exceeded: {self.max_calls} calls per {self.window_seconds}s"
                )

            # Add current timestamp
            timestamps.append(now)

            logger.debug(
                "rate_limiter: %s allowed for %s (%d/%d calls)",
                identity,
                self.key_prefix,
                len(timestamps),
                self.max_calls,
            )

    def reset(self, identity: str) -> None:
        """
        Reset rate limit counter for *identity*.

        Useful for testing or admin overrides.

        Parameters
        ----------
        identity : str
            Unique identifier to reset
        """
        key = self._redis_key(identity)
        r = _get_redis()

        if r is not None:
            try:
                r.delete(key)
                logger.debug("rate_limiter: reset %s for %s (redis)", identity, self.key_prefix)
            except Exception as exc:
                logger.warning("rate_limiter: Redis delete error (%s)", exc)

        with _mem_lock:
            if key in _mem_windows:
                del _mem_windows[key]
                logger.debug("rate_limiter: reset %s for %s (memory)", identity, self.key_prefix)

    def remaining(self, identity: str) -> int:
        """
        Get remaining calls available for *identity*.

        Parameters
        ----------
        identity : str
            Unique identifier to check

        Returns
        -------
        int
            Number of remaining calls (0 if at or over limit)
        """
        r = _get_redis()

        if r is not None:
            return self._remaining_redis(r, identity)
        else:
            return self._remaining_memory(identity)

    def _remaining_redis(self, r: Any, identity: str) -> int:
        """Get remaining calls from Redis."""
        key = self._redis_key(identity)
        now = time.time()
        window_start = now - self.window_seconds

        try:
            # Remove expired entries and count
            pipe = r.pipeline()
            pipe.zremrangebyscore(key, 0, window_start)
            pipe.zcard(key)
            results = pipe.execute()

            current_count = results[1]
            remaining = max(0, self.max_calls - current_count)
            return remaining

        except Exception as exc:
            logger.warning("rate_limiter: Redis error checking remaining (%s)", exc)
            return self._remaining_memory(identity)

    def _remaining_memory(self, identity: str) -> int:
        """Get remaining calls from memory."""
        key = self._redis_key(identity)
        now = time.monotonic()
        window_start = now - self.window_seconds

        with _mem_lock:
            timestamps = _mem_windows.get(key, [])
            # Count valid timestamps in window
            valid_count = sum(1 for ts in timestamps if ts > window_start)
            remaining = max(0, self.max_calls - valid_count)
            return remaining
