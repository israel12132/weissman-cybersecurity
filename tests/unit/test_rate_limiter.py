"""
tests/unit/test_rate_limiter.py
================================
Unit tests for rate limiting module.

Run with: pytest tests/unit/test_rate_limiter.py -v
"""

import time
from unittest.mock import Mock, patch, MagicMock

import pytest

from src.rate_limiter import RateLimiter, _get_redis
from src.exceptions import RateLimitExceeded


class TestRateLimiterMemory:
    """Tests for in-memory rate limiting (no Redis)."""

    @pytest.fixture(autouse=True)
    def setup(self):
        """Reset in-memory state before each test."""
        from src.rate_limiter import _mem_windows
        _mem_windows.clear()
        # Patch Redis to return None for memory-only tests
        with patch("src.rate_limiter._get_redis", return_value=None):
            yield

    def test_allows_requests_within_limit(self):
        """Should allow requests within the limit."""
        limiter = RateLimiter(key_prefix="test", max_calls=3, window_seconds=60)

        # Should allow 3 requests
        limiter.check("user1")
        limiter.check("user1")
        limiter.check("user1")

        # Fourth request should raise exception
        with pytest.raises(RateLimitExceeded) as exc_info:
            limiter.check("user1")

        assert "Rate limit exceeded" in str(exc_info.value)
        assert exc_info.value.context["identity"] == "user1"
        assert exc_info.value.context["max_calls"] == 3

    def test_separate_identities_tracked_independently(self):
        """Should track different identities separately."""
        limiter = RateLimiter(key_prefix="test", max_calls=2, window_seconds=60)

        limiter.check("user1")
        limiter.check("user1")

        # user1 is at limit, but user2 should still work
        limiter.check("user2")
        limiter.check("user2")

        # Both should now be at limit
        with pytest.raises(RateLimitExceeded):
            limiter.check("user1")

        with pytest.raises(RateLimitExceeded):
            limiter.check("user2")

    def test_sliding_window_expires_old_requests(self):
        """Should expire requests outside the time window."""
        limiter = RateLimiter(key_prefix="test", max_calls=2, window_seconds=1)

        limiter.check("user1")
        limiter.check("user1")

        # At limit now
        with pytest.raises(RateLimitExceeded):
            limiter.check("user1")

        # Wait for window to expire
        time.sleep(1.1)

        # Should work again
        limiter.check("user1")

    def test_reset_clears_identity(self):
        """Should reset rate limit for specific identity."""
        limiter = RateLimiter(key_prefix="test", max_calls=2, window_seconds=60)

        limiter.check("user1")
        limiter.check("user1")

        # At limit
        with pytest.raises(RateLimitExceeded):
            limiter.check("user1")

        # Reset
        limiter.reset("user1")

        # Should work now
        limiter.check("user1")

    def test_remaining_returns_correct_count(self):
        """Should return correct remaining call count."""
        limiter = RateLimiter(key_prefix="test", max_calls=5, window_seconds=60)

        assert limiter.remaining("user1") == 5

        limiter.check("user1")
        assert limiter.remaining("user1") == 4

        limiter.check("user1")
        limiter.check("user1")
        assert limiter.remaining("user1") == 2

    def test_remaining_returns_zero_at_limit(self):
        """Should return 0 when at limit."""
        limiter = RateLimiter(key_prefix="test", max_calls=2, window_seconds=60)

        limiter.check("user1")
        limiter.check("user1")

        assert limiter.remaining("user1") == 0

    def test_multiple_limiters_independent(self):
        """Different limiter instances should be independent."""
        limiter1 = RateLimiter(key_prefix="scan", max_calls=2, window_seconds=60)
        limiter2 = RateLimiter(key_prefix="export", max_calls=2, window_seconds=60)

        limiter1.check("user1")
        limiter1.check("user1")

        # limiter1 is at limit but limiter2 should work
        limiter2.check("user1")
        limiter2.check("user1")

        with pytest.raises(RateLimitExceeded):
            limiter1.check("user1")

        with pytest.raises(RateLimitExceeded):
            limiter2.check("user1")


class TestRateLimiterRedis:
    """Tests for Redis-based rate limiting."""

    @pytest.fixture
    def mock_redis(self):
        """Create a mock Redis client."""
        redis_mock = MagicMock()
        redis_mock.ping.return_value = True

        # Mock pipeline
        pipe_mock = MagicMock()
        pipe_mock.execute.return_value = [None, 0, None, None]  # [zremrangebyscore, zcard, zadd, expire]
        redis_mock.pipeline.return_value = pipe_mock

        return redis_mock

    def test_uses_redis_when_available(self, mock_redis):
        """Should use Redis when available."""
        with patch("src.rate_limiter._get_redis", return_value=mock_redis):
            limiter = RateLimiter(key_prefix="test", max_calls=5, window_seconds=60)
            limiter.check("user1")

            # Should have called Redis pipeline
            assert mock_redis.pipeline.called

    def test_redis_enforces_limit(self, mock_redis):
        """Should enforce limit using Redis."""
        # Mock Redis to return count at limit
        pipe_mock = mock_redis.pipeline.return_value
        pipe_mock.execute.return_value = [None, 5, None, None]  # 5 requests already

        with patch("src.rate_limiter._get_redis", return_value=mock_redis):
            limiter = RateLimiter(key_prefix="test", max_calls=5, window_seconds=60)

            with pytest.raises(RateLimitExceeded):
                limiter.check("user1")

    def test_redis_fallback_on_error(self, mock_redis):
        """Should fall back to memory on Redis error."""
        # Make Redis raise exception
        mock_redis.pipeline.side_effect = Exception("Redis connection failed")

        with patch("src.rate_limiter._get_redis", return_value=mock_redis):
            limiter = RateLimiter(key_prefix="test", max_calls=3, window_seconds=60)

            # Should not raise, should fall back to memory
            limiter.check("user1")

    def test_redis_key_format(self):
        """Should use correct key format."""
        limiter = RateLimiter(key_prefix="scan_trigger", max_calls=5, window_seconds=60)
        key = limiter._redis_key("tenant123")

        assert key == "weissman:rl:scan_trigger:tenant123"

    def test_reset_deletes_redis_key(self, mock_redis):
        """Should delete Redis key on reset."""
        with patch("src.rate_limiter._get_redis", return_value=mock_redis):
            limiter = RateLimiter(key_prefix="test", max_calls=5, window_seconds=60)
            limiter.reset("user1")

            assert mock_redis.delete.called


class TestRateLimiterConfiguration:
    """Tests for rate limiter configuration and edge cases."""

    def test_accepts_valid_configuration(self):
        """Should accept valid configuration."""
        limiter = RateLimiter(key_prefix="test", max_calls=10, window_seconds=60)
        assert limiter.key_prefix == "test"
        assert limiter.max_calls == 10
        assert limiter.window_seconds == 60

    def test_very_short_window(self):
        """Should handle very short time windows."""
        limiter = RateLimiter(key_prefix="test", max_calls=2, window_seconds=1)

        limiter.check("user1")
        limiter.check("user1")

        with pytest.raises(RateLimitExceeded):
            limiter.check("user1")

        time.sleep(1.1)
        limiter.check("user1")  # Should work now

    def test_single_request_limit(self):
        """Should handle limit of 1 request."""
        limiter = RateLimiter(key_prefix="test", max_calls=1, window_seconds=60)

        limiter.check("user1")

        with pytest.raises(RateLimitExceeded):
            limiter.check("user1")

    def test_exception_includes_context(self):
        """Rate limit exception should include useful context."""
        limiter = RateLimiter(key_prefix="scan", max_calls=3, window_seconds=60)

        limiter.check("tenant123")
        limiter.check("tenant123")
        limiter.check("tenant123")

        with pytest.raises(RateLimitExceeded) as exc_info:
            limiter.check("tenant123")

        exc = exc_info.value
        assert exc.context["identity"] == "tenant123"
        assert exc.context["key_prefix"] == "scan"
        assert exc.context["max_calls"] == 3
        assert exc.context["current_calls"] >= 3
        assert exc.context["window_seconds"] == 60


class TestRateLimiterIntegration:
    """Integration tests simulating real usage patterns."""

    def test_burst_then_steady_rate(self):
        """Should handle burst followed by steady rate."""
        limiter = RateLimiter(key_prefix="test", max_calls=5, window_seconds=2)

        # Burst: 5 quick requests
        for _ in range(5):
            limiter.check("user1")

        # Should be at limit
        with pytest.raises(RateLimitExceeded):
            limiter.check("user1")

        # Wait for window to partially expire
        time.sleep(1)

        # Should still be at limit (window not expired)
        with pytest.raises(RateLimitExceeded):
            limiter.check("user1")

        # Wait for full window expiry
        time.sleep(1.1)

        # Should work now
        limiter.check("user1")

    def test_multiple_tenants_concurrent(self):
        """Should handle multiple tenants concurrently."""
        limiter = RateLimiter(key_prefix="api", max_calls=2, window_seconds=60)

        # Simulate multiple tenants
        tenants = ["tenant1", "tenant2", "tenant3"]

        for tenant in tenants:
            limiter.check(tenant)
            limiter.check(tenant)

            with pytest.raises(RateLimitExceeded):
                limiter.check(tenant)

    def test_ip_based_limiting(self):
        """Should work with IP addresses as identity."""
        limiter = RateLimiter(key_prefix="login", max_calls=3, window_seconds=60)

        ip = "192.168.1.100"

        limiter.check(ip)
        limiter.check(ip)
        limiter.check(ip)

        with pytest.raises(RateLimitExceeded):
            limiter.check(ip)


class TestGetRedis:
    """Tests for Redis connection management."""

    def test_returns_none_when_no_redis_url(self):
        """Should return None when REDIS_URL not set."""
        with patch.dict("os.environ", {}, clear=True):
            # Clear cached client
            import src.rate_limiter
            src.rate_limiter._redis_client = None

            redis = _get_redis()
            assert redis is None

    def test_lazy_initialization(self):
        """Should initialize Redis lazily."""
        with patch("src.rate_limiter.REDIS_URL", "redis://localhost:6379"):
            with patch("redis.from_url") as mock_from_url:
                mock_client = MagicMock()
                mock_client.ping.return_value = True
                mock_from_url.return_value = mock_client

                # Clear cached client
                import src.rate_limiter
                src.rate_limiter._redis_client = None

                # First call should initialize
                redis1 = _get_redis()
                assert redis1 is not None

                # Second call should return cached client
                redis2 = _get_redis()
                assert redis2 is redis1

                # Should only call from_url once
                assert mock_from_url.call_count == 1

    def test_handles_redis_connection_failure(self):
        """Should handle Redis connection failure gracefully."""
        with patch("src.rate_limiter.REDIS_URL", "redis://localhost:6379"):
            with patch("redis.from_url") as mock_from_url:
                mock_from_url.side_effect = Exception("Connection refused")

                # Clear cached client
                import src.rate_limiter
                src.rate_limiter._redis_client = None

                redis = _get_redis()
                assert redis is None
