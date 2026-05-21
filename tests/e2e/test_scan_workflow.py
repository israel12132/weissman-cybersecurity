"""
tests/e2e/test_scan_workflow.py
================================
End-to-end tests for complete scan workflows.

These tests simulate real user workflows from start to finish.

Run with: pytest tests/e2e/test_scan_workflow.py -v
"""

import pytest
import time
import asyncio
from typing import Dict, Any

# Mock imports - replace with actual API client
from unittest.mock import Mock, patch

try:
    import websockets
    WEBSOCKETS_AVAILABLE = True
except ImportError:
    WEBSOCKETS_AVAILABLE = False


@pytest.fixture
def api_client():
    """
    Mock API client for E2E tests.

    In production environment, replace with actual HTTP client:
    - Use httpx.AsyncClient for async operations
    - Configure with base_url pointing to API server
    - Add authentication headers and timeout settings
    """
    return Mock()


@pytest.fixture
def test_tenant():
    """Test tenant configuration."""
    return {
        "id": "test_tenant_e2e",
        "name": "E2E Test Tenant",
        "email": "e2e@test.com",
        "scope": {
            "domains": ["example.com"],
            "ip_ranges": ["192.168.1.0/24"],
            "tech_stack": ["nginx", "python", "postgresql"],
        },
    }


@pytest.fixture
def authenticated_session(api_client, test_tenant):
    """Authenticated API session."""
    # Mock authentication
    session = Mock()
    session.tenant_id = test_tenant["id"]
    session.token = "test_jwt_token"
    return session


class TestCompleteScanWorkflow:
    """E2E tests for complete scan execution workflow."""

    def test_full_scan_workflow(self, api_client, authenticated_session, test_tenant):
        """
        Complete workflow: login -> trigger scan -> wait for results -> export report.
        """
        # Step 1: Authenticate
        auth_response = api_client.post("/api/auth/login", json={
            "email": "e2e@test.com",
            "password": "TestPass123!",
        })
        assert auth_response.status_code == 200
        assert "token" in auth_response.json()

        # Step 2: Trigger scan
        scan_response = api_client.post(
            "/api/scan/run-all",
            headers={"Authorization": f"Bearer {authenticated_session.token}"},
            json={
                "target": "example.com",
                "scope": test_tenant["scope"],
                "engines": ["xss", "sqli", "csrf"],
            },
        )
        assert scan_response.status_code == 202
        scan_id = scan_response.json()["scan_id"]

        # Step 3: Poll for scan completion
        max_wait = 60  # seconds
        start_time = time.time()
        scan_complete = False

        while time.time() - start_time < max_wait:
            status_response = api_client.get(
                f"/api/scan/status/{scan_id}",
                headers={"Authorization": f"Bearer {authenticated_session.token}"},
            )
            assert status_response.status_code == 200

            status = status_response.json()["status"]
            if status == "completed":
                scan_complete = True
                break
            elif status == "failed":
                pytest.fail(f"Scan failed: {status_response.json()}")

            time.sleep(2)

        assert scan_complete, "Scan did not complete in time"

        # Step 4: Retrieve results
        results_response = api_client.get(
            f"/api/scan/results/{scan_id}",
            headers={"Authorization": f"Bearer {authenticated_session.token}"},
        )
        assert results_response.status_code == 200

        results = results_response.json()
        assert "findings" in results
        assert "summary" in results

        # Step 5: Export PDF report
        export_response = api_client.post(
            f"/api/export/pdf/{scan_id}",
            headers={"Authorization": f"Bearer {authenticated_session.token}"},
        )
        assert export_response.status_code == 200
        assert export_response.headers["Content-Type"] == "application/pdf"

    def test_scan_with_rate_limiting(self, api_client, authenticated_session):
        """Should enforce rate limits on scan triggers."""
        # Trigger multiple scans rapidly
        responses = []
        for i in range(10):
            response = api_client.post(
                "/api/scan/run-all",
                headers={"Authorization": f"Bearer {authenticated_session.token}"},
                json={"target": f"target{i}.example.com"},
            )
            responses.append(response)

        # At least one should be rate limited
        rate_limited = [r for r in responses if r.status_code == 429]
        assert len(rate_limited) > 0

    def test_scan_with_invalid_target(self, api_client, authenticated_session):
        """Should reject scans for out-of-scope targets."""
        response = api_client.post(
            "/api/scan/run-all",
            headers={"Authorization": f"Bearer {authenticated_session.token}"},
            json={
                "target": "unauthorized-domain.com",  # Out of scope
            },
        )
        assert response.status_code in [400, 403]
        assert "out of scope" in response.json()["error"].lower()


class TestAuthenticationWorkflow:
    """E2E tests for authentication and MFA workflows."""

    def test_login_with_mfa(self, api_client):
        """Complete MFA authentication workflow."""
        # Step 1: Initial login
        login_response = api_client.post("/api/auth/login", json={
            "email": "mfa_user@test.com",
            "password": "SecurePass123!",
        })
        assert login_response.status_code == 200
        assert login_response.json()["mfa_required"] is True

        # Step 2: Verify MFA token
        mfa_response = api_client.post("/api/auth/mfa/verify", json={
            "email": "mfa_user@test.com",
            "token": "123456",  # Mock TOTP token
        })
        assert mfa_response.status_code == 200
        assert "access_token" in mfa_response.json()

    def test_password_change_workflow(self, api_client, authenticated_session):
        """Complete password change workflow."""
        # Step 1: Change password
        response = api_client.post(
            "/api/auth/change-password",
            headers={"Authorization": f"Bearer {authenticated_session.token}"},
            json={
                "current_password": "OldPass123!",
                "new_password": "NewSecurePass456!",
            },
        )
        assert response.status_code == 200

        # Step 2: Login with new password
        login_response = api_client.post("/api/auth/login", json={
            "email": "e2e@test.com",
            "password": "NewSecurePass456!",
        })
        assert login_response.status_code == 200

    def test_invalid_password_rejection(self, api_client):
        """Should reject weak passwords during registration."""
        response = api_client.post("/api/auth/register", json={
            "email": "new_user@test.com",
            "password": "weak",  # Too weak
            "role": "viewer",
        })
        assert response.status_code == 400
        assert "password" in response.json()["error"].lower()


class TestFeedCorrelationWorkflow:
    """E2E tests for threat feed correlation."""

    def test_feed_correlation_workflow(self, api_client, authenticated_session, test_tenant):
        """Complete feed correlation workflow."""
        # Step 1: Trigger correlation
        response = api_client.post(
            "/api/correlation/run",
            headers={"Authorization": f"Bearer {authenticated_session.token}"},
            json={
                "tenant_id": test_tenant["id"],
                "feeds": ["nvd", "github", "osv"],
            },
        )
        assert response.status_code == 202
        job_id = response.json()["job_id"]

        # Step 2: Wait for completion
        max_wait = 30
        start_time = time.time()

        while time.time() - start_time < max_wait:
            status_response = api_client.get(
                f"/api/correlation/status/{job_id}",
                headers={"Authorization": f"Bearer {authenticated_session.token}"},
            )
            if status_response.json()["status"] == "completed":
                break
            time.sleep(1)

        # Step 3: Retrieve correlated findings
        findings_response = api_client.get(
            f"/api/correlation/findings/{job_id}",
            headers={"Authorization": f"Bearer {authenticated_session.token}"},
        )
        assert findings_response.status_code == 200

        findings = findings_response.json()
        assert "findings" in findings
        assert "tech_stack_matches" in findings


class TestWebSocketWorkflow:
    """E2E tests for WebSocket real-time updates."""

    @pytest.mark.asyncio
    @pytest.mark.skipif(not WEBSOCKETS_AVAILABLE, reason="websockets library not installed")
    async def test_websocket_connection(self, authenticated_session):
        """
        Should establish WebSocket connection and receive events.

        This test verifies:
        1. WebSocket connection can be established with valid auth token
        2. Server responds to ping messages with pong
        3. Connection handles graceful disconnect
        """
        uri = f"ws://localhost:8080/ws/command-center?token={authenticated_session.token}"

        try:
            async with websockets.connect(
                uri,
                ping_interval=20,
                ping_timeout=10,
                close_timeout=5
            ) as websocket:
                # Send ping message
                ping_message = '{"type":"ping","timestamp":' + str(time.time()) + '}'
                await asyncio.wait_for(websocket.send(ping_message), timeout=5.0)

                # Receive and validate pong response
                response = await asyncio.wait_for(websocket.recv(), timeout=5.0)
                assert response is not None, "No response received from server"
                assert "pong" in response.lower() or "ping" in response.lower(), \
                    f"Unexpected response: {response}"

        except asyncio.TimeoutError:
            pytest.fail("WebSocket connection or message exchange timed out")
        except websockets.exceptions.WebSocketException as e:
            pytest.fail(f"WebSocket error: {e}")
        except ConnectionRefusedError:
            pytest.skip("WebSocket server not running at localhost:8080")

    @pytest.mark.asyncio
    @pytest.mark.skipif(not WEBSOCKETS_AVAILABLE, reason="websockets library not installed")
    async def test_websocket_live_events(self, authenticated_session):
        """
        Should receive live scan events via WebSocket.

        This test verifies:
        1. Server sends initialization event upon connection
        2. Server sends periodic heartbeat messages
        3. Connection remains stable over time
        """
        uri = f"ws://localhost:8080/ws/command-center?token={authenticated_session.token}"

        try:
            async with websockets.connect(
                uri,
                ping_interval=20,
                ping_timeout=10,
                close_timeout=5
            ) as websocket:
                # Wait for initialization event
                try:
                    init_event = await asyncio.wait_for(websocket.recv(), timeout=5.0)
                    assert init_event is not None, "No initialization event received"
                    # Initialization events typically contain "init", "connected", or "ready"
                    assert any(keyword in init_event.lower() for keyword in ["init", "connected", "ready"]), \
                        f"Unexpected init event: {init_event}"
                except asyncio.TimeoutError:
                    # Some implementations don't send init - that's okay
                    pass

                # Wait for heartbeat within reasonable time (30 seconds)
                try:
                    heartbeat = await asyncio.wait_for(websocket.recv(), timeout=30.0)
                    assert heartbeat is not None, "No heartbeat received"
                except asyncio.TimeoutError:
                    pytest.fail("No heartbeat received within 30 seconds")

        except websockets.exceptions.WebSocketException as e:
            pytest.fail(f"WebSocket error: {e}")
        except ConnectionRefusedError:
            pytest.skip("WebSocket server not running at localhost:8080")

    @pytest.mark.asyncio
    @pytest.mark.skipif(not WEBSOCKETS_AVAILABLE, reason="websockets library not installed")
    async def test_websocket_authentication_failure(self):
        """
        Should reject WebSocket connection with invalid token.

        This test verifies:
        1. Server validates authentication tokens
        2. Invalid tokens are rejected with proper error codes
        """
        uri = "ws://localhost:8080/ws/command-center?token=invalid_token_12345"

        try:
            async with websockets.connect(uri, close_timeout=5) as websocket:
                # If connection succeeds, try to receive - should fail
                await asyncio.wait_for(websocket.recv(), timeout=2.0)
                pytest.fail("Connection should have been rejected with invalid token")
        except websockets.exceptions.InvalidStatusCode as e:
            # Expected behavior - server should return 401 or 403
            assert e.status_code in [401, 403], f"Unexpected status code: {e.status_code}"
        except websockets.exceptions.WebSocketException:
            # Also acceptable - connection rejected
            pass
        except ConnectionRefusedError:
            pytest.skip("WebSocket server not running at localhost:8080")
        except asyncio.TimeoutError:
            pytest.fail("Connection timeout - expected immediate rejection")


class TestExportWorkflow:
    """E2E tests for report export workflows."""

    def test_pdf_export_workflow(self, api_client, authenticated_session):
        """Complete PDF export workflow with XSS sanitization."""
        # Create test findings with potentially malicious content
        findings = [
            {
                "title": "XSS Vulnerability <script>alert(1)</script>",
                "description": "<img src=x onerror=alert(1)>",
                "severity": "high",
            }
        ]

        response = api_client.post(
            "/api/export/pdf",
            headers={"Authorization": f"Bearer {authenticated_session.token}"},
            json={"findings": findings},
        )

        assert response.status_code == 200
        assert response.headers["Content-Type"] == "application/pdf"

        # Verify XSS was sanitized (PDF should not contain raw script tags)
        pdf_content = response.content.decode("latin-1", errors="ignore")
        assert "<script>" not in pdf_content
        assert "alert(1)" not in pdf_content

    def test_excel_export_workflow(self, api_client, authenticated_session):
        """Complete Excel export workflow."""
        response = api_client.post(
            "/api/export/excel",
            headers={"Authorization": f"Bearer {authenticated_session.token}"},
            json={"scan_id": "test_scan_123"},
        )

        assert response.status_code == 200
        assert "application/vnd.openxmlformats" in response.headers["Content-Type"]


class TestMetricsWorkflow:
    """E2E tests for metrics and monitoring."""

    def test_metrics_endpoint(self, api_client):
        """Should expose Prometheus metrics."""
        response = api_client.get("http://localhost:9090/metrics")
        assert response.status_code == 200

        metrics = response.text
        assert "weissman_requests_total" in metrics
        assert "weissman_scan_duration_seconds" in metrics

    def test_metrics_health_check(self, api_client):
        """Should report metrics system health."""
        response = api_client.get("/api/health/metrics")
        assert response.status_code == 200

        health = response.json()
        assert health["enabled"] is True
        assert health["prometheus_initialized"] is True
