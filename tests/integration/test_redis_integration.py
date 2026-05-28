"""
tests/integration/test_redis_integration.py
===========================================
Integration tests for Redis operations.

These tests require a Redis server to be running.
Set TEST_REDIS_URL environment variable or use docker-compose.

Run with: pytest tests/integration/test_redis_integration.py -v
"""

import os
import time
import pytest

from src.rate_limiter import RateLimiter
from src.feed_cache import get_cached_feed, set_cached_feed, invalidate_feed
from src.exceptions import RateLimitExceeded


# Test Redis URL
TEST_REDIS_URL = os.getenv("TEST_REDIS_URL", "redis://localhost:6379/15")


@pytest.fixture(scope="session", autouse=True)
def setup_test_redis():
    """Configure Redis for tests."""
    import redis

    client = redis.from_url(TEST_REDIS_URL, decode_responses=True)
    try:
        client.ping()
    except Exception as e:
        pytest.skip(
            f"Redis is not reachable at {TEST_REDIS_URL} ({type(e).__name__}: {e})",
        )
    finally:
        try:
            client.close()
        except Exception:
            pass

    os.environ["REDIS_URL"] = TEST_REDIS_URL
    yield
    # Cleanup
    if "REDIS_URL" in os.environ:
        del os.environ["REDIS_URL"]


@pytest.fixture
def redis_client():
    """Get Redis client for cleanup."""
    import redis
    client = redis.from_url(TEST_REDIS_URL, decode_responses=True)

    yield client

    # Cleanup all test keys
    keys = list(client.scan_iter(match="weissman:*"))
    if keys:
        client.delete(*keys)
    client.close()


class TestRateLimiterRedisIntegration:
    """Integration tests for rate limiter with Redis."""

    def test_redis_rate_limiting(self, redis_client):
        """Should enforce rate limits using Redis."""
        limiter = RateLimiter(key_prefix="test_api", max_calls=3, window_seconds=2)

        # Should allow 3 requests
        limiter.check("user123")
        limiter.check("user123")
        limiter.check("user123")

        # Fourth should be blocked
        with pytest.raises(RateLimitExceeded) as exc_info:
            limiter.check("user123")

        assert "user123" in str(exc_info.value)
        assert "test_api" in str(exc_info.value)

    def test_redis_sliding_window(self, redis_client):
        """Should use sliding window algorithm."""
        limiter = RateLimiter(key_prefix="test_sliding", max_calls=5, window_seconds=2)

        # Use all 5 calls
        for _ in range(5):
            limiter.check("user456")

        # Should be blocked
        with pytest.raises(RateLimitExceeded):
            limiter.check("user456")

        # Wait for window to slide
        time.sleep(2.1)

        # Should work now
        limiter.check("user456")

    def test_redis_per_tenant_isolation(self, redis_client):
        """Should isolate rate limits per tenant."""
        limiter = RateLimiter(key_prefix="test_tenant", max_calls=2, window_seconds=60)

        # Tenant A
        limiter.check("tenant_a")
        limiter.check("tenant_a")

        # Tenant A blocked
        with pytest.raises(RateLimitExceeded):
            limiter.check("tenant_a")

        # Tenant B should still work
        limiter.check("tenant_b")
        limiter.check("tenant_b")

    def test_redis_reset(self, redis_client):
        """Should reset rate limit counter."""
        limiter = RateLimiter(key_prefix="test_reset", max_calls=2, window_seconds=60)

        limiter.check("user789")
        limiter.check("user789")

        # At limit
        with pytest.raises(RateLimitExceeded):
            limiter.check("user789")

        # Reset
        limiter.reset("user789")

        # Should work now
        limiter.check("user789")

    def test_redis_remaining_count(self, redis_client):
        """Should accurately track remaining calls."""
        limiter = RateLimiter(key_prefix="test_remaining", max_calls=5, window_seconds=60)

        assert limiter.remaining("user_xyz") == 5

        limiter.check("user_xyz")
        assert limiter.remaining("user_xyz") == 4

        limiter.check("user_xyz")
        limiter.check("user_xyz")
        assert limiter.remaining("user_xyz") == 2

    def test_redis_key_expiration(self, redis_client):
        """Should set TTL on Redis keys."""
        limiter = RateLimiter(key_prefix="test_ttl", max_calls=3, window_seconds=5)

        limiter.check("user_ttl")

        # Check key exists with TTL
        key = "weissman:rl:test_ttl:user_ttl"
        ttl = redis_client.ttl(key)
        assert ttl > 0
        assert ttl <= 15  # window_seconds + 10


class TestFeedCacheRedisIntegration:
    """Integration tests for feed cache with Redis."""

    def test_redis_cache_set_get(self, redis_client):
        """Should store and retrieve cached feeds."""
        findings = [
            {"id": "CVE-2024-1234", "severity": "high"},
            {"id": "CVE-2024-5678", "severity": "medium"},
        ]

        set_cached_feed("test_feed_1", findings)

        cached = get_cached_feed("test_feed_1")

        assert cached is not None
        assert len(cached) == 2
        assert cached[0]["id"] == "CVE-2024-1234"

    def test_redis_cache_miss(self, redis_client):
        """Should return None on cache miss."""
        cached = get_cached_feed("nonexistent_feed")
        assert cached is None

    def test_redis_cache_expiration(self, redis_client):
        """Should expire cached feeds after TTL."""
        # Set short TTL for testing
        os.environ["FEED_CACHE_TTL_SECONDS"] = "1"

        findings = [{"id": "test"}]
        set_cached_feed("test_expire", findings)

        # Should be cached
        cached = get_cached_feed("test_expire")
        assert cached is not None

        # Wait for expiration
        time.sleep(1.5)

        # Should be expired
        cached = get_cached_feed("test_expire")
        assert cached is None

        # Cleanup
        del os.environ["FEED_CACHE_TTL_SECONDS"]

    def test_redis_cache_invalidation(self, redis_client):
        """Should invalidate specific cache entries."""
        findings = [{"id": "test"}]
        set_cached_feed("test_invalidate", findings)

        # Should be cached
        assert get_cached_feed("test_invalidate") is not None

        # Invalidate
        invalidate_feed("test_invalidate")

        # Should be gone
        assert get_cached_feed("test_invalidate") is None

    def test_redis_cache_empty_results(self, redis_client):
        """Should cache empty results."""
        set_cached_feed("test_empty", [], cache_empty=True)

        cached = get_cached_feed("test_empty")
        assert cached is not None
        assert len(cached) == 0

    def test_redis_cache_large_payload(self, redis_client):
        """Should handle large cached payloads."""
        # Create large payload
        findings = [
            {"id": f"CVE-2024-{i:04d}", "description": "x" * 1000}
            for i in range(1000)
        ]

        set_cached_feed("test_large", findings)
        cached = get_cached_feed("test_large")

        assert cached is not None
        assert len(cached) == 1000


class TestRedisPersistence:
    """Tests for Redis persistence and reliability."""

    def test_redis_concurrent_access(self, redis_client):
        """Should handle concurrent access safely."""
        import threading

        limiter = RateLimiter(key_prefix="test_concurrent", max_calls=100, window_seconds=60)
        errors = []

        def worker(identity):
            try:
                limiter.check(identity)
            except Exception as e:
                errors.append(e)

        # Spawn 50 concurrent requests
        threads = []
        for i in range(50):
            thread = threading.Thread(target=worker, args=(f"user_{i % 10}",))
            threads.append(thread)
            thread.start()

        for thread in threads:
            thread.join()

        # Should have some rate limit errors but no crashes
        assert len([e for e in errors if isinstance(e, RateLimitExceeded)]) > 0

    def test_redis_pipeline_atomicity(self, redis_client):
        """Should use pipelines for atomic operations."""
        limiter = RateLimiter(key_prefix="test_atomic", max_calls=5, window_seconds=60)

        # Multiple calls should be atomic
        for i in range(5):
            limiter.check(f"atomic_user_{i}")

        # Verify all keys created
        keys = list(redis_client.scan_iter(match="weissman:rl:test_atomic:*"))
        assert len(keys) == 5


class TestRedisFailover:
    """Tests for Redis failover scenarios."""

    def test_redis_connection_failure_fallback(self, redis_client):
        """Should fall back to memory on Redis failure."""
        # Temporarily break Redis connection
        os.environ["REDIS_URL"] = "redis://invalid-host:6379/0"

        # Force re-init
        import src.rate_limiter
        src.rate_limiter._redis_client = None

        limiter = RateLimiter(key_prefix="test_fallback", max_calls=2, window_seconds=60)

        # Should work with memory backend
        limiter.check("fallback_user")
        limiter.check("fallback_user")

        with pytest.raises(RateLimitExceeded):
            limiter.check("fallback_user")

        # Restore
        os.environ["REDIS_URL"] = TEST_REDIS_URL
        src.rate_limiter._redis_client = None

    def test_redis_operation_timeout(self, redis_client):
        """Should handle operation timeouts gracefully."""
        # Redis operations should have reasonable timeouts
        limiter = RateLimiter(key_prefix="test_timeout", max_calls=5, window_seconds=60)

        import time
        start = time.time()
        limiter.check("timeout_user")
        duration = time.time() - start

        # Should complete quickly (< 100ms)
        assert duration < 0.1
