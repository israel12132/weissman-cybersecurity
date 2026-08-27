"""Live scan pipeline contract (requires running weissman-server + worker).

Skip when WEISSMAN_E2E_BASE is unset. Run via:
  ./scripts/run_e2e_stack.sh start
  WEISSMAN_E2E_BASE=http://127.0.0.1:8000 pytest tests/e2e/test_scan_pipeline_live.py -v
"""

from __future__ import annotations

import json
import math
import os
import time

import httpx
import pytest

BASE = os.environ.get("WEISSMAN_E2E_BASE", "").rstrip("/")
EMAIL = os.environ.get("WEISSMAN_ADMIN_EMAIL", "admin@localhost")
PASSWORD = os.environ.get("WEISSMAN_ADMIN_PASSWORD", "")
TENANT = os.environ.get("WEISSMAN_E2E_TENANT", "default")
POLL_MS = int(os.environ.get("WEISSMAN_E2E_POLL_MS", "2000"))
POLL_MAX = int(os.environ.get("WEISSMAN_E2E_POLL_MAX", "90"))

pytestmark = pytest.mark.skipif(
    not BASE or not PASSWORD,
    reason="Set WEISSMAN_E2E_BASE and WEISSMAN_ADMIN_PASSWORD for live E2E",
)


# Ceiling on a single honored Retry-After wait. Must exceed the largest hint the server sends
# (60s, login per-IP limit) — see _request_with_retry.
_WAIT_CAP_S = 75.0
# Ceiling on CUMULATIVE back-off (mirrors scripts/lib/scan_intake.mjs WAIT_TOTAL_BUDGET_MS).
# One 60s login-window wait plus a short second attempt; six uncapped 60s sleeps would
# burn six minutes of CI after a shed that a single window already clears.
_WAIT_TOTAL_BUDGET_S = 90.0


def _positive_seconds(raw: object) -> float | None:
    try:
        wait = float(raw)  # type: ignore[arg-type]
    except (TypeError, ValueError):
        return None
    if not math.isfinite(wait) or wait <= 0:
        return None
    return wait


def _retry_after_seconds(resp: httpx.Response, url: str) -> float | None:
    """Honor the server's back-off hint.

    Prefer the `Retry-After` header, then JSON `retry_after_seconds`. CI observed
    429s on `/api/login` whose JSON carried `retry_after_seconds: 60` while a
    header-only client used a 0.4s fallback, burned the remaining quota, and
    failed the fixture in ~6s. Login 429s without any hint default to the
    documented 60s per-IP window (`http/login_rate_limit.rs`).
    """
    hinted = _positive_seconds(resp.headers.get("retry-after"))
    if hinted is not None:
        return hinted
    try:
        body = resp.json()
    except (ValueError, json.JSONDecodeError, httpx.DecodingError):
        body = None
    if isinstance(body, dict):
        hinted = _positive_seconds(body.get("retry_after_seconds"))
        if hinted is not None:
            return hinted
    if "/api/login" in url:
        return 60.0
    return None


def _request_with_retry(
    inner: httpx.Client, method: str, url: str, *, _retries: int = 6, **kwargs
) -> httpx.Response:
    """Retry while scan intake is shed transiently, honoring Retry-After. Two distinct codes, both
    self-protecting and both advertising Retry-After precisely so a correct client waits and retries
    instead of failing the contract:
      * 429 `rate_limited` — the live stack drives all traffic through a single IP (127.0.0.1), so a
        legitimate burst can trip the 30/s-per-IP limit no real client ever hits;
      * 503 `load_shed` — self-heal recovery sheds new scan intake when the DB pool or async backlog
        crosses its critical threshold, and auto-clears on a TTL as the platform drains.
    The cap must stay ABOVE every Retry-After the server actually sends, or honoring the hint is
    silently defeated: a 20s cap truncated the login limiter's documented 60s hint (see
    http/login_rate_limit.rs, `retry_after_secs = 60`) to a third of the requested wait, so the
    retries burned out inside one quota window and every test errored on the /api/login fixture
    with 429 once the earlier live steps had spent the per-IP budget. 75s clears the 60s login hint
    and the 15s load-shed hint with margin. This only raises the CEILING on a wait the server itself
    asked for — the healthy path still waits exactly the hint, so it costs nothing when nothing is
    throttled."""
    resp = inner.request(method, url, **kwargs)
    attempt = 0
    spent = 0.0
    while resp.status_code in (429, 503) and attempt < _retries:
        fallback = 1.5 * (attempt + 1)
        wait = _retry_after_seconds(resp, url)
        if wait is None:
            wait = fallback
        wait = min(wait, _WAIT_CAP_S)
        if spent + wait > _WAIT_TOTAL_BUDGET_S:
            break
        print(
            f"… {method} {url} shed (HTTP {resp.status_code}); "
            f"backing off {wait:.0f}s (retry {attempt + 1}/{_retries})",
            flush=True,
        )
        time.sleep(wait)
        spent += wait
        resp = inner.request(method, url, **kwargs)
        attempt += 1
    return resp


class _RetryClient:
    """httpx.Client facade whose get/post transparently ride out 429 throttling (see above)."""

    def __init__(self, inner: httpx.Client) -> None:
        self._inner = inner

    def get(self, url: str, **kwargs) -> httpx.Response:
        return _request_with_retry(self._inner, "GET", url, **kwargs)

    def post(self, url: str, **kwargs) -> httpx.Response:
        return _request_with_retry(self._inner, "POST", url, **kwargs)


@pytest.fixture(scope="module")
def client() -> _RetryClient:
    with httpx.Client(base_url=BASE, timeout=60.0) as c:
        yield _RetryClient(c)


@pytest.fixture(scope="module")
def auth_headers(client: httpx.Client) -> dict[str, str]:
    r = client.post(
        "/api/login",
        json={"email": EMAIL, "password": PASSWORD, "tenant_slug": TENANT},
    )
    r.raise_for_status()
    data = r.json()
    token = data.get("access_token") or data.get("token")
    assert token, "login returned no access_token"
    return {"Authorization": f"Bearer {token}"}


def _poll_job(client: httpx.Client, headers: dict[str, str], job_id: str) -> str:
    terminal = {"completed", "done", "failed", "error", "dead", "cancelled"}
    for _ in range(POLL_MAX):
        r = client.get(f"/api/jobs/{job_id}", headers=headers)
        if r.status_code == 200:
            status = str(r.json().get("status", "")).lower()
            if status in terminal:
                return status
        time.sleep(POLL_MS / 1000)
    return "timeout"


def test_health_and_login(client: httpx.Client, auth_headers: dict[str, str]) -> None:
    assert client.get("/api/health").status_code == 200
    assert client.get("/api/clients", headers=auth_headers).status_code == 200


def test_scan_enqueue_and_complete(client: httpx.Client, auth_headers: dict[str, str]) -> None:
    clients = client.get("/api/clients", headers=auth_headers).json()
    assert isinstance(clients, list)
    client_id = clients[0]["id"] if clients else None
    if not client_id:
        created = client.post(
            "/api/clients",
            headers=auth_headers,
            json={
                "name": "Py E2E Client",
                "domains": '["https://example.com"]',
                "ip_ranges": '["127.0.0.0/8"]',
            },
        )
        created.raise_for_status()
        client_id = created.json()["id"]

    scan = client.post(
        "/api/command-center/scan",
        headers=auth_headers,
        json={
            "engine": "zero_day_radar",
            "client_id": int(client_id),
        },
    )
    assert scan.status_code == 202, scan.text
    job_id = scan.json()["job_id"]
    status = _poll_job(client, auth_headers, job_id)
    assert status == "completed", f"job {job_id} ended as {status}"


def test_scope_rejection(client: httpx.Client, auth_headers: dict[str, str]) -> None:
    clients = client.get("/api/clients", headers=auth_headers).json()
    client_id = clients[0]["id"]
    bad = client.post(
        "/api/command-center/scan",
        headers=auth_headers,
        json={
            "engine": "microsecond_timing",
            "client_id": int(client_id),
            "target": "https://not-in-client-scope.invalid",
        },
    )
    assert bad.status_code in (400, 403)


def test_job_payload_secrets_redacted(client: httpx.Client, auth_headers: dict[str, str]) -> None:
    clients = client.get("/api/clients", headers=auth_headers).json()
    client_id = clients[0]["id"]
    # Distinctive plaintext sentinel: if the server echoes the secret back
    # anywhere in the job payload it will appear verbatim. A pre-redacted mask
    # (e.g. "••••") would make this test pass even with no redaction at all.
    sentinel = "ghp_SENTINEL_DO_NOT_ECHO_0123456789"
    scan = client.post(
        "/api/command-center/scan",
        headers=auth_headers,
        json={
            "engine": "microsecond_timing",
            "client_id": int(client_id),
            "target": "https://example.com",
            "github_token": sentinel,
        },
    )
    assert scan.status_code == 202
    job_id = scan.json()["job_id"]
    payload = client.get(f"/api/jobs/{job_id}", headers=auth_headers).json().get("payload", {})
    assert sentinel not in json.dumps(payload), "github_token must not be echoed raw to client"


def test_findings_api_after_scan(client: httpx.Client, auth_headers: dict[str, str]) -> None:
    clients = client.get("/api/clients", headers=auth_headers).json()
    client_id = int(clients[0]["id"])
    r = client.get(f"/api/findings?client_id={client_id}&limit=10", headers=auth_headers)
    r.raise_for_status()
    body = r.json()
    assert body.get("ok") is True
    assert isinstance(body.get("findings"), list)
    assert "total" in body
    for row in body["findings"]:
        cm = row.get("confidence_multiplier")
        er = row.get("effective_risk", row.get("risk_score"))
        if cm is not None:
            assert 0.1 <= float(cm) <= 1.0
        if er is not None:
            assert 0.0 <= float(er) <= 10.0
