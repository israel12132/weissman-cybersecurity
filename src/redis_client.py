"""
src/redis_client.py
===================
Shared Redis client initialization with double-check locking pattern.

This module consolidates Redis initialization logic that was previously
duplicated across feed_cache.py and rate_limiter.py, preventing future
code duplication and ensuring consistent Redis configuration.

Usage:
    from src.redis_client import get_shared_redis_client

    redis = get_shared_redis_client()
    if redis:
        redis.set("key", "value")
"""

import logging
import os
import threading
from typing import Any, Optional

logger = logging.getLogger("weissman.redis_client")

REDIS_URL: Optional[str] = os.environ.get("REDIS_URL")

_redis_client: Optional[Any] = None
_redis_init_lock = threading.Lock()


def get_shared_redis_client() -> Optional[Any]:
    """
    Lazy-init Redis client with double-check locking pattern.

    Returns:
        Redis client instance if connection successful, None otherwise.

    Thread-safe: Uses double-check locking to ensure only one client
    is created even in multi-threaded environments.

    Fallback: Returns None if REDIS_URL is not configured or if
    connection fails, allowing callers to implement in-memory fallbacks.
    """
    global _redis_client

    # First check without lock (fast path)
    if _redis_client is not None:
        return _redis_client

    # No Redis URL configured
    if not REDIS_URL:
        return None

    # Double-check locking pattern
    with _redis_init_lock:
        # Second check with lock (slow path)
        if _redis_client is not None:
            return _redis_client

        try:
            import redis

            client = redis.from_url(
                REDIS_URL,
                socket_timeout=2,
                decode_responses=True
            )

            # Test connection
            client.ping()

            _redis_client = client
            logger.info("Redis client initialized successfully (url=%s)", REDIS_URL[:20] + "...")
            return _redis_client

        except Exception as exc:
            logger.warning(
                "Redis connection failed (%s) — callers will use in-memory fallback",
                exc
            )
            _redis_client = None
            return None


def reset_redis_client() -> None:
    """
    Reset Redis client (for testing purposes only).

    This function should only be called in test fixtures to ensure
    clean state between tests.
    """
    global _redis_client
    with _redis_init_lock:
        _redis_client = None
