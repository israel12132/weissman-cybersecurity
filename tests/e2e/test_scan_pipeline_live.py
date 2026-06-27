"""Live scan pipeline contract (requires running weissman-server + worker).

Skip when WEISSMAN_E2E_BASE is unset. Run via:
  ./scripts/run_e2e_stack.sh start
  WEISSMAN_E2E_BASE=http://127.0.0.1:8000 pytest tests/e2e/test_scan_pipeline_live.py -v
"""

from __future__ import annotations

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


@pytest.fixture(scope="module")
def client() -> httpx.Client:
    with httpx.Client(base_url=BASE, timeout=60.0) as c:
        yield c


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
    scan = client.post(
        "/api/command-center/scan",
        headers=auth_headers,
        json={
            "engine": "microsecond_timing",
            "client_id": int(client_id),
            "target": "https://example.com",
            "github_token": "••••••••",
        },
    )
    assert scan.status_code == 202
    job_id = scan.json()["job_id"]
    payload = client.get(f"/api/jobs/{job_id}", headers=auth_headers).json().get("payload", {})
    raw = payload.get("github_token")
    if raw is not None:
        assert "••••" in str(raw) or raw == "", "github_token must not be echoed raw to client"


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
