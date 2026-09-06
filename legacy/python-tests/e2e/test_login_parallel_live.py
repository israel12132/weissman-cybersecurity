"""Live login contract: parallel valid auth must succeed; stuffing still 429s.

Skip when WEISSMAN_E2E_BASE / WEISSMAN_ADMIN_PASSWORD are unset. Run via:
  ./scripts/run_e2e_stack.sh start
  WEISSMAN_E2E_BASE=http://127.0.0.1:8000 pytest tests/e2e/test_login_parallel_live.py -v

Login endpoint is POST /api/login (not /api/auth/login).
"""

from __future__ import annotations

import os
from concurrent.futures import ThreadPoolExecutor, as_completed

import httpx
import pytest

BASE = os.environ.get("WEISSMAN_E2E_BASE", "").rstrip("/")
EMAIL = os.environ.get("WEISSMAN_ADMIN_EMAIL", "admin@localhost")
PASSWORD = os.environ.get("WEISSMAN_ADMIN_PASSWORD", "")
TENANT = os.environ.get("WEISSMAN_E2E_TENANT", "default")
PARALLEL = int(os.environ.get("WEISSMAN_LOGIN_PARALLEL_N", "24"))

pytestmark = pytest.mark.skipif(
    not BASE or not PASSWORD,
    reason="Set WEISSMAN_E2E_BASE and WEISSMAN_ADMIN_PASSWORD for live E2E",
)


def _login(client: httpx.Client, email: str, password: str) -> httpx.Response:
    return client.post(
        f"{BASE}/api/login",
        json={"email": email, "password": password, "tenant_slug": TENANT},
        timeout=30.0,
    )


def test_parallel_valid_logins_from_ci_must_succeed() -> None:
    """N concurrent valid POSTs to /api/login from one IP must not 429."""

    def one() -> int:
        with httpx.Client() as client:
            resp = _login(client, EMAIL, PASSWORD)
            return resp.status_code

    codes: list[int] = []
    with ThreadPoolExecutor(max_workers=PARALLEL) as pool:
        futs = [pool.submit(one) for _ in range(PARALLEL)]
        for fut in as_completed(futs):
            codes.append(fut.result())

    assert codes, "no responses"
    assert all(c == 200 for c in codes), (
        f"legitimate parallel logins must succeed; got {sorted(codes)} "
        f"(429 means stuffing defense is still counting successes)"
    )


def test_credential_stuffing_is_still_blocked() -> None:
    """A burst of failed logins from one IP must trip login_ip_locked / 429."""
    # Unique fake emails so per-email lockout does not mask the per-IP stuffing gate.
    codes: list[int] = []
    bodies: list[str] = []
    with httpx.Client(timeout=30.0) as client:
        for i in range(40):
            resp = _login(client, f"stuffing-{i}@invalid.example", "wrong-password-not-real")
            codes.append(resp.status_code)
            bodies.append(resp.text)
            if resp.status_code == 429:
                payload = resp.json()
                assert payload.get("code") in {"login_ip_locked", "login_locked", "rate_limited"}
                break
    assert 429 in codes, f"stuffing burst must 429; got {codes} bodies={bodies[-3:]}"
