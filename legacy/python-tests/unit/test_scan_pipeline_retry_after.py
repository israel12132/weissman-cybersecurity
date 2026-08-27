"""Unit tests for live-pipeline 429 Retry-After parsing (no live server)."""

import httpx

from tests.e2e import test_scan_pipeline_live as live


def test_retry_after_prefers_header_over_json() -> None:
    resp = httpx.Response(
        429, headers={"Retry-After": "60"}, json={"retry_after_seconds": 1}
    )
    assert live._retry_after_seconds(resp, "http://x/api/jobs") == 60.0


def test_retry_after_reads_json_when_header_missing() -> None:
    resp = httpx.Response(429, json={"retry_after_seconds": 60})
    assert live._retry_after_seconds(resp, "http://x/api/jobs") == 60.0


def test_login_defaults_to_sixty_seconds_without_hint() -> None:
    resp = httpx.Response(429, json={"ok": False, "code": "rate_limited"})
    assert live._retry_after_seconds(resp, "http://127.0.0.1:18000/api/login") == 60.0


def test_non_login_without_hint_is_none() -> None:
    resp = httpx.Response(429, json={"ok": False})
    assert live._retry_after_seconds(resp, "http://x/api/jobs") is None


def test_positive_seconds_rejects_junk() -> None:
    assert live._positive_seconds("nope") is None
    assert live._positive_seconds(-1) is None
    assert live._positive_seconds(float("nan")) is None
    assert live._positive_seconds(15) == 15.0
