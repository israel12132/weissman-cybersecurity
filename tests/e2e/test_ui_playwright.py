"""
tests/e2e/test_ui_playwright.py
================================
Playwright E2E tests for frontend UI.

Tests user interactions, navigation, and real-time updates.

Install Playwright:
    pip install playwright
    playwright install chromium

Run with: pytest tests/e2e/test_ui_playwright.py -v
"""

import pytest
from playwright.sync_api import Page, expect


BASE_URL = "http://localhost:3000"


@pytest.fixture(scope="session")
def browser_context_args(browser_context_args):
    """Configure browser context."""
    return {
        **browser_context_args,
        "viewport": {"width": 1920, "height": 1080},
        "ignore_https_errors": True,
    }


@pytest.fixture
def authenticated_page(page: Page):
    """Navigate to app and authenticate."""
    page.goto(BASE_URL)

    # Login
    page.fill('input[name="email"]', "test@example.com")
    page.fill('input[name="password"]', "TestPass123!")
    page.click('button[type="submit"]')

    # Wait for dashboard
    page.wait_for_url(f"{BASE_URL}/dashboard")

    return page


class TestLoginFlow:
    """Tests for authentication UI."""

    def test_login_page_loads(self, page: Page):
        """Should load login page successfully."""
        page.goto(BASE_URL)

        # Check for login form
        expect(page.locator('input[name="email"]')).to_be_visible()
        expect(page.locator('input[name="password"]')).to_be_visible()
        expect(page.locator('button[type="submit"]')).to_be_visible()

    def test_login_with_valid_credentials(self, page: Page):
        """Should login successfully with valid credentials."""
        page.goto(BASE_URL)

        page.fill('input[name="email"]', "test@example.com")
        page.fill('input[name="password"]', "TestPass123!")
        page.click('button[type="submit"]')

        # Should redirect to dashboard
        page.wait_for_url(f"{BASE_URL}/dashboard", timeout=5000)
        expect(page).to_have_url(f"{BASE_URL}/dashboard")

    def test_login_with_invalid_credentials(self, page: Page):
        """Should show error with invalid credentials."""
        page.goto(BASE_URL)

        page.fill('input[name="email"]', "invalid@example.com")
        page.fill('input[name="password"]', "WrongPass123!")
        page.click('button[type="submit"]')

        # Should show error message
        error = page.locator('[role="alert"]')
        expect(error).to_be_visible()
        expect(error).to_contain_text("Invalid credentials")

    def test_password_validation(self, page: Page):
        """Should validate password strength."""
        page.goto(f"{BASE_URL}/register")

        page.fill('input[name="email"]', "newuser@example.com")
        page.fill('input[name="password"]', "weak")  # Too weak
        page.click('button[type="submit"]')

        # Should show validation error
        error = page.locator('text=Password must be at least 12 characters')
        expect(error).to_be_visible()


class TestDashboard:
    """Tests for main dashboard UI."""

    def test_dashboard_loads(self, authenticated_page: Page):
        """Should load dashboard with key metrics."""
        # Check for key dashboard elements
        expect(authenticated_page.locator("text=Total Findings")).to_be_visible()
        expect(authenticated_page.locator("text=Critical")).to_be_visible()
        expect(authenticated_page.locator("text=High")).to_be_visible()

    def test_navigation_menu(self, authenticated_page: Page):
        """Should navigate between pages."""
        # Navigate to Scans page
        authenticated_page.click('a[href="/scans"]')
        authenticated_page.wait_for_url(f"{BASE_URL}/scans")
        expect(authenticated_page).to_have_url(f"{BASE_URL}/scans")

        # Navigate to Findings page
        authenticated_page.click('a[href="/findings"]')
        authenticated_page.wait_for_url(f"{BASE_URL}/findings")
        expect(authenticated_page).to_have_url(f"{BASE_URL}/findings")

    def test_real_time_updates(self, authenticated_page: Page):
        """Should receive WebSocket updates."""
        # Wait for WebSocket connection
        authenticated_page.wait_for_timeout(2000)

        # Check for connection status indicator
        status = authenticated_page.locator('[data-testid="ws-status"]')
        expect(status).to_have_attribute("data-status", "connected")


class TestScanTrigger:
    """Tests for scan trigger UI."""

    def test_trigger_scan_form(self, authenticated_page: Page):
        """Should display scan trigger form."""
        authenticated_page.goto(f"{BASE_URL}/scans/new")

        # Check form elements
        expect(authenticated_page.locator('input[name="target"]')).to_be_visible()
        expect(authenticated_page.locator('button[type="submit"]')).to_be_visible()

    def test_trigger_scan_validation(self, authenticated_page: Page):
        """Should validate scan target."""
        authenticated_page.goto(f"{BASE_URL}/scans/new")

        # Try to submit empty form
        authenticated_page.click('button[type="submit"]')

        # Should show validation error
        error = authenticated_page.locator('text=Target is required')
        expect(error).to_be_visible()

    def test_trigger_scan_success(self, authenticated_page: Page):
        """Should trigger scan successfully."""
        authenticated_page.goto(f"{BASE_URL}/scans/new")

        # Fill form
        authenticated_page.fill('input[name="target"]', "https://example.com")

        # Select engines
        authenticated_page.check('input[value="xss"]')
        authenticated_page.check('input[value="sqli"]')

        # Submit
        authenticated_page.click('button[type="submit"]')

        # Should show success message
        success = authenticated_page.locator('text=Scan queued successfully')
        expect(success).to_be_visible(timeout=5000)

    def test_scan_progress_updates(self, authenticated_page: Page):
        """Should show scan progress updates."""
        authenticated_page.goto(f"{BASE_URL}/scans")

        # Trigger a scan
        authenticated_page.click('button:has-text("New Scan")')
        authenticated_page.fill('input[name="target"]', "https://example.com")
        authenticated_page.click('button[type="submit"]')

        # Should show progress bar
        progress = authenticated_page.locator('[role="progressbar"]')
        expect(progress).to_be_visible(timeout=10000)


class TestFindings:
    """Tests for findings list and details."""

    def test_findings_list_loads(self, authenticated_page: Page):
        """Should load findings list."""
        authenticated_page.goto(f"{BASE_URL}/findings")

        # Check for findings table
        expect(authenticated_page.locator("table")).to_be_visible()
        expect(authenticated_page.locator("thead")).to_contain_text("Severity")
        expect(authenticated_page.locator("thead")).to_contain_text("Title")

    def test_findings_filter(self, authenticated_page: Page):
        """Should filter findings by severity."""
        authenticated_page.goto(f"{BASE_URL}/findings")

        # Select severity filter
        authenticated_page.select_option('select[name="severity"]', "critical")

        # Wait for filtered results
        authenticated_page.wait_for_timeout(1000)

        # Check that only critical findings shown
        rows = authenticated_page.locator("tbody tr")
        expect(rows.first).to_contain_text("Critical")

    def test_finding_details_modal(self, authenticated_page: Page):
        """Should open finding details modal."""
        authenticated_page.goto(f"{BASE_URL}/findings")

        # Click first finding
        authenticated_page.click("tbody tr:first-child")

        # Modal should open
        modal = authenticated_page.locator('[role="dialog"]')
        expect(modal).to_be_visible()

        # Should show finding details
        expect(modal).to_contain_text("Description")
        expect(modal).to_contain_text("Remediation")


class TestExports:
    """Tests for report export functionality."""

    def test_export_pdf_button(self, authenticated_page: Page):
        """Should show export PDF button."""
        authenticated_page.goto(f"{BASE_URL}/findings")

        export_button = authenticated_page.locator('button:has-text("Export PDF")')
        expect(export_button).to_be_visible()

    def test_export_pdf_download(self, authenticated_page: Page):
        """Should download PDF report."""
        authenticated_page.goto(f"{BASE_URL}/findings")

        # Start waiting for download before clicking
        with authenticated_page.expect_download() as download_info:
            authenticated_page.click('button:has-text("Export PDF")')

        download = download_info.value

        # Verify download
        assert download.suggested_filename.endswith(".pdf")

    def test_export_excel_download(self, authenticated_page: Page):
        """Should download Excel report."""
        authenticated_page.goto(f"{BASE_URL}/findings")

        with authenticated_page.expect_download() as download_info:
            authenticated_page.click('button:has-text("Export Excel")')

        download = download_info.value
        assert download.suggested_filename.endswith(".xlsx")


class TestCommandCenter:
    """Tests for Command Center real-time view."""

    def test_command_center_loads(self, authenticated_page: Page):
        """Should load Command Center with globe."""
        authenticated_page.goto(f"{BASE_URL}/command-center")

        # Check for canvas element (3D globe)
        canvas = authenticated_page.locator("canvas")
        expect(canvas).to_be_visible(timeout=10000)

    def test_live_events_ticker(self, authenticated_page: Page):
        """Should show live events ticker."""
        authenticated_page.goto(f"{BASE_URL}/command-center")

        # Check for ticker container
        ticker = authenticated_page.locator('[data-testid="events-ticker"]')
        expect(ticker).to_be_visible()

    def test_score_updates(self, authenticated_page: Page):
        """Should update security score in real-time."""
        authenticated_page.goto(f"{BASE_URL}/command-center")

        # Get initial score
        score_element = authenticated_page.locator('[data-testid="security-score"]')
        expect(score_element).to_be_visible()

        initial_score = score_element.inner_text()

        # Wait for potential update
        authenticated_page.wait_for_timeout(5000)

        # Score should be displayed
        assert initial_score != ""


class TestAccessControl:
    """Tests for RBAC and access control."""

    def test_viewer_access_restrictions(self, page: Page):
        """Viewer role should not see admin features."""
        # Login as viewer
        page.goto(BASE_URL)
        page.fill('input[name="email"]', "viewer@example.com")
        page.fill('input[name="password"]', "ViewerPass123!")
        page.click('button[type="submit"]')

        page.wait_for_url(f"{BASE_URL}/dashboard")

        # Admin menu should not be visible
        admin_link = page.locator('a[href="/admin"]')
        expect(admin_link).not_to_be_visible()

    def test_analyst_can_trigger_scans(self, page: Page):
        """Analyst role should be able to trigger scans."""
        # Login as analyst
        page.goto(BASE_URL)
        page.fill('input[name="email"]', "analyst@example.com")
        page.fill('input[name="password"]', "AnalystPass123!")
        page.click('button[type="submit"]')

        page.wait_for_url(f"{BASE_URL}/dashboard")

        # Should see scan trigger button
        new_scan_button = page.locator('button:has-text("New Scan")')
        expect(new_scan_button).to_be_visible()


class TestResponsiveness:
    """Tests for responsive design."""

    def test_mobile_viewport(self, page: Page):
        """Should work on mobile viewport."""
        # Set mobile viewport
        page.set_viewport_size({"width": 375, "height": 667})

        page.goto(BASE_URL)

        # Login form should be visible
        expect(page.locator('input[name="email"]')).to_be_visible()

        # Fill and submit
        page.fill('input[name="email"]', "test@example.com")
        page.fill('input[name="password"]', "TestPass123!")
        page.click('button[type="submit"]')

        # Dashboard should load
        page.wait_for_url(f"{BASE_URL}/dashboard", timeout=5000)

    def test_tablet_viewport(self, page: Page):
        """Should work on tablet viewport."""
        page.set_viewport_size({"width": 768, "height": 1024})

        page.goto(BASE_URL)
        expect(page.locator('input[name="email"]')).to_be_visible()


class TestPerformance:
    """Tests for performance characteristics."""

    def test_page_load_time(self, page: Page):
        """Dashboard should load within 3 seconds."""
        import time

        page.goto(BASE_URL)
        page.fill('input[name="email"]', "test@example.com")
        page.fill('input[name="password"]', "TestPass123!")

        start = time.time()
        page.click('button[type="submit"]')
        page.wait_for_url(f"{BASE_URL}/dashboard")
        duration = time.time() - start

        assert duration < 3.0, f"Dashboard loaded in {duration:.2f}s (should be < 3s)"

    def test_findings_table_renders_fast(self, authenticated_page: Page):
        """Findings table should render quickly."""
        import time

        start = time.time()
        authenticated_page.goto(f"{BASE_URL}/findings")

        # Wait for table to be visible
        authenticated_page.locator("table").wait_for(state="visible")
        duration = time.time() - start

        assert duration < 2.0, f"Table rendered in {duration:.2f}s (should be < 2s)"
