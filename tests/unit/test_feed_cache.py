"""
tests/unit/test_feed_cache.py
==============================
Unit tests for the feed caching layer in src/feed_cache.py.

Tests cover both the in-memory and Redis-backed paths.
Redis is always mocked so tests run without a running Redis instance.

Run with: pytest tests/unit/test_feed_cache.py -v
"""

import time
from dataclasses import dataclass
from unittest.mock import MagicMock, patch

import pytest

import src.feed_cache as feed_cache_module
from src.feed_cache import (
    CACHE_KEY_PREFIX,
    get_cached_feed,
    invalidate_all_feeds,
    invalidate_feed,
    set_cached_feed,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

@dataclass
class _Finding:
    """Minimal dataclass to exercise dataclass serialisation path."""
    id: str
    severity: str


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture(autouse=True)
def clear_mem_cache():
    """Reset in-memory cache and force Redis to be unavailable before each test."""
    feed_cache_module._mem_cache.clear()
    with patch("src.feed_cache._get_redis", return_value=None):
        yield
    feed_cache_module._mem_cache.clear()


# ---------------------------------------------------------------------------
# get_cached_feed – cache miss
# ---------------------------------------------------------------------------

class TestGetCachedFeedMiss:
    def test_returns_none_on_empty_cache(self):
        result = get_cached_feed("nonexistent_key")
        assert result is None

    def test_returns_none_for_different_key(self):
        set_cached_feed("key_a", [{"cve": "CVE-1"}])
        result = get_cached_feed("key_b")
        assert result is None


# ---------------------------------------------------------------------------
# set_cached_feed / get_cached_feed – in-memory round-trip
# ---------------------------------------------------------------------------

class TestInMemoryRoundTrip:
    def test_stores_and_retrieves_dict_findings(self):
        findings = [{"cve": "CVE-2024-1234", "severity": "high"}]
        set_cached_feed("nvd_recent", findings)
        result = get_cached_feed("nvd_recent")
        assert result == findings

    def test_stores_and_retrieves_multiple_items(self):
        findings = [{"id": str(i)} for i in range(5)]
        set_cached_feed("multi", findings)
        result = get_cached_feed("multi")
        assert len(result) == 5

    def test_stores_pydantic_like_objects(self):
        """Objects with model_dump() should be serialised correctly."""

        class PydanticLike:
            def model_dump(self, mode="json"):
                return {"field": "value"}

        obj = PydanticLike()
        set_cached_feed("pydantic_key", [obj])
        result = get_cached_feed("pydantic_key")
        assert result == [{"field": "value"}]

    def test_stores_dataclass_objects(self):
        findings = [_Finding(id="f1", severity="critical")]
        set_cached_feed("dc_key", findings)
        result = get_cached_feed("dc_key")
        assert result == [{"id": "f1", "severity": "critical"}]

    def test_empty_list_cached_by_default(self):
        set_cached_feed("empty_key", [])
        result = get_cached_feed("empty_key")
        assert result == []

    def test_empty_list_not_cached_when_cache_empty_false(self):
        set_cached_feed("empty_skip", [], cache_empty=False)
        result = get_cached_feed("empty_skip")
        assert result is None

    def test_overwrite_existing_entry(self):
        set_cached_feed("key", [{"v": 1}])
        set_cached_feed("key", [{"v": 2}])
        result = get_cached_feed("key")
        assert result == [{"v": 2}]

    def test_separate_keys_independent(self):
        set_cached_feed("key1", [{"a": 1}])
        set_cached_feed("key2", [{"b": 2}])
        assert get_cached_feed("key1") == [{"a": 1}]
        assert get_cached_feed("key2") == [{"b": 2}]


# ---------------------------------------------------------------------------
# TTL expiry (in-memory)
# ---------------------------------------------------------------------------

class TestInMemoryTTL:
    def test_expired_entry_returns_none(self, monkeypatch):
        """Entry older than TTL should be treated as a miss."""
        # Write into the internal dict with a past expiry timestamp
        full_key = CACHE_KEY_PREFIX + "expired_key"
        import json
        raw = json.dumps([{"id": "old"}])
        # Set expiry in the past (already expired)
        feed_cache_module._mem_cache[full_key] = (time.monotonic() - 1, raw)

        result = get_cached_feed("expired_key")
        assert result is None
        # Expired entry should be evicted
        assert full_key not in feed_cache_module._mem_cache

    def test_fresh_entry_is_returned(self):
        """Entry within TTL should be returned normally."""
        set_cached_feed("fresh_key", [{"id": "new"}])
        result = get_cached_feed("fresh_key")
        assert result is not None
        assert result == [{"id": "new"}]


# ---------------------------------------------------------------------------
# invalidate_feed
# ---------------------------------------------------------------------------

class TestInvalidateFeed:
    def test_invalidate_removes_entry(self):
        set_cached_feed("target", [{"x": 1}])
        assert get_cached_feed("target") is not None

        invalidate_feed("target")
        assert get_cached_feed("target") is None

    def test_invalidate_nonexistent_key_is_safe(self):
        # Should not raise
        invalidate_feed("does_not_exist")

    def test_invalidate_only_removes_target_key(self):
        set_cached_feed("keep", [{"k": 1}])
        set_cached_feed("remove", [{"r": 1}])

        invalidate_feed("remove")

        assert get_cached_feed("keep") == [{"k": 1}]
        assert get_cached_feed("remove") is None


# ---------------------------------------------------------------------------
# invalidate_all_feeds
# ---------------------------------------------------------------------------

class TestInvalidateAllFeeds:
    def test_clears_all_entries(self):
        set_cached_feed("a", [{"a": 1}])
        set_cached_feed("b", [{"b": 2}])
        set_cached_feed("c", [{"c": 3}])

        invalidate_all_feeds()

        assert get_cached_feed("a") is None
        assert get_cached_feed("b") is None
        assert get_cached_feed("c") is None

    def test_safe_when_cache_already_empty(self):
        feed_cache_module._mem_cache.clear()
        # Should not raise
        invalidate_all_feeds()


# ---------------------------------------------------------------------------
# Redis-backed paths (mocked Redis)
# ---------------------------------------------------------------------------

class TestRedisBackedPaths:
    """Verify that the Redis code paths are exercised when Redis is available."""

    @pytest.fixture(autouse=True)
    def redis_available(self):
        """Override the autouse fixture: provide a mock Redis client."""
        self.mock_redis = MagicMock()
        with patch("src.feed_cache._get_redis", return_value=self.mock_redis):
            yield

    def test_set_uses_setex(self):
        findings = [{"cve": "CVE-2024-9999"}]
        set_cached_feed("nvd_key", findings)
        self.mock_redis.setex.assert_called_once()
        args = self.mock_redis.setex.call_args[0]
        assert args[0] == CACHE_KEY_PREFIX + "nvd_key"

    def test_get_returns_none_on_redis_miss(self):
        self.mock_redis.get.return_value = None
        result = get_cached_feed("missing")
        assert result is None

    def test_get_returns_findings_on_redis_hit(self):
        import json
        payload = json.dumps([{"cve": "CVE-2024-1111"}])
        self.mock_redis.get.return_value = payload.encode()
        result = get_cached_feed("hit_key")
        assert result == [{"cve": "CVE-2024-1111"}]

    def test_invalidate_calls_delete(self):
        invalidate_feed("some_key")
        self.mock_redis.delete.assert_called_once_with(CACHE_KEY_PREFIX + "some_key")

    def test_invalidate_all_calls_scan_iter_and_delete(self):
        full_key = (CACHE_KEY_PREFIX + "x").encode()
        self.mock_redis.scan_iter.return_value = [full_key]
        invalidate_all_feeds()
        self.mock_redis.delete.assert_called_once_with(full_key)

    def test_redis_setex_error_is_swallowed(self):
        self.mock_redis.setex.side_effect = ConnectionError("Redis down")
        # Should not raise
        set_cached_feed("safe_key", [{"x": 1}])

    def test_redis_get_error_falls_back_to_none(self):
        self.mock_redis.get.side_effect = ConnectionError("Redis down")
        result = get_cached_feed("safe_key")
        assert result is None

    def test_get_returns_none_on_corrupt_json(self):
        """Corrupt JSON in Redis should be swallowed gracefully (returns None)."""
        self.mock_redis.get.return_value = b"NOT_VALID_JSON!!!"
        result = get_cached_feed("corrupt")
        assert result is None
