"""
tests/unit/test_exceptions.py
==============================
Unit tests for the structured exception hierarchy in src/exceptions.py.

Run with: pytest tests/unit/test_exceptions.py -v
"""

import pytest

from src.exceptions import (
    # Base
    WeissmanError,
    # Auth
    AuthenticationError,
    InvalidCredentialsError,
    MFARequiredError,
    MFAInvalidError,
    AuthorizationError,
    InsufficientRoleError,
    # Password / rate-limit
    InvalidPasswordError,
    RateLimitExceeded,
    # Scan / engine
    ScanError,
    InvalidTargetError,
    ScanTimeoutError,
    EngineError,
    # Database
    DatabaseError,
    TenantNotFoundError,
    VulnerabilityNotFoundError,
    # Export
    ExportError,
    PDFGenerationError,
    SanitizationError,
    # Feed
    FeedError,
    FeedTimeoutError,
    FeedParseError,
    # Webhook
    WebhookError,
    WebhookDeliveryError,
    WebhookValidationError,
    # Other
    ConfigurationError,
    CacheError,
    RedisConnectionError,
    ValidationError,
    InvalidInputError,
    # Map
    HTTP_EXCEPTION_MAP,
)


# ---------------------------------------------------------------------------
# WeissmanError base class
# ---------------------------------------------------------------------------

class TestWeissmanError:
    """Tests for the WeissmanError base class."""

    def test_is_exception_subclass(self):
        assert issubclass(WeissmanError, Exception)

    def test_message_stored(self):
        err = WeissmanError("something went wrong")
        assert err.message == "something went wrong"
        assert str(err) == "something went wrong"

    def test_context_stored(self):
        err = WeissmanError("oops", tenant_id="t1", code=42)
        assert err.context == {"tenant_id": "t1", "code": 42}

    def test_str_includes_context(self):
        err = WeissmanError("oops", key="val")
        result = str(err)
        assert "oops" in result
        assert "key=val" in result

    def test_str_without_context(self):
        err = WeissmanError("plain")
        assert str(err) == "plain"

    def test_no_context_by_default(self):
        err = WeissmanError("msg")
        assert err.context == {}

    def test_can_be_raised_and_caught(self):
        with pytest.raises(WeissmanError) as exc_info:
            raise WeissmanError("boom", x=1)
        assert exc_info.value.context["x"] == 1


# ---------------------------------------------------------------------------
# Authentication & Authorization hierarchy
# ---------------------------------------------------------------------------

class TestAuthExceptionHierarchy:
    """Tests for authentication and authorization exception hierarchy."""

    def test_authentication_error_is_weissman_error(self):
        assert issubclass(AuthenticationError, WeissmanError)

    def test_invalid_credentials_is_authentication_error(self):
        assert issubclass(InvalidCredentialsError, AuthenticationError)

    def test_mfa_required_is_authentication_error(self):
        assert issubclass(MFARequiredError, AuthenticationError)

    def test_mfa_invalid_is_authentication_error(self):
        assert issubclass(MFAInvalidError, AuthenticationError)

    def test_authorization_error_is_weissman_error(self):
        assert issubclass(AuthorizationError, WeissmanError)

    def test_insufficient_role_is_authorization_error(self):
        assert issubclass(InsufficientRoleError, AuthorizationError)

    def test_raise_invalid_credentials(self):
        with pytest.raises(AuthenticationError):
            raise InvalidCredentialsError("bad creds")

    def test_raise_insufficient_role_with_context(self):
        with pytest.raises(InsufficientRoleError) as exc_info:
            raise InsufficientRoleError(
                "Insufficient role",
                required="super_admin",
                current="viewer",
            )
        assert exc_info.value.context["required"] == "super_admin"
        assert exc_info.value.context["current"] == "viewer"


# ---------------------------------------------------------------------------
# Password & Rate-limit
# ---------------------------------------------------------------------------

class TestPasswordAndRateLimit:
    def test_invalid_password_is_weissman_error(self):
        assert issubclass(InvalidPasswordError, WeissmanError)

    def test_rate_limit_exceeded_is_weissman_error(self):
        assert issubclass(RateLimitExceeded, WeissmanError)

    def test_rate_limit_context_fields(self):
        err = RateLimitExceeded(
            "Rate limit exceeded",
            identity="tenant123",
            current_calls=10,
            max_calls=5,
        )
        assert err.context["identity"] == "tenant123"
        assert err.context["current_calls"] == 10
        assert err.context["max_calls"] == 5

    def test_invalid_password_message(self):
        err = InvalidPasswordError("Password too short")
        assert "Password too short" in str(err)


# ---------------------------------------------------------------------------
# Scan & Engine
# ---------------------------------------------------------------------------

class TestScanExceptionHierarchy:
    def test_scan_error_is_weissman_error(self):
        assert issubclass(ScanError, WeissmanError)

    def test_invalid_target_is_scan_error(self):
        assert issubclass(InvalidTargetError, ScanError)

    def test_scan_timeout_is_scan_error(self):
        assert issubclass(ScanTimeoutError, ScanError)

    def test_engine_error_is_scan_error(self):
        assert issubclass(EngineError, ScanError)

    def test_raise_invalid_target(self):
        with pytest.raises(ScanError):
            raise InvalidTargetError("bad target", url="ftp://bad")

    def test_engine_error_with_context(self):
        err = EngineError("engine crashed", engine_id="sqli_001")
        assert err.context["engine_id"] == "sqli_001"


# ---------------------------------------------------------------------------
# Database
# ---------------------------------------------------------------------------

class TestDatabaseExceptionHierarchy:
    def test_database_error_is_weissman_error(self):
        assert issubclass(DatabaseError, WeissmanError)

    def test_tenant_not_found_is_database_error(self):
        assert issubclass(TenantNotFoundError, DatabaseError)

    def test_vulnerability_not_found_is_database_error(self):
        assert issubclass(VulnerabilityNotFoundError, DatabaseError)

    def test_raise_tenant_not_found(self):
        with pytest.raises(DatabaseError):
            raise TenantNotFoundError("no such tenant", tenant_id="xyz")


# ---------------------------------------------------------------------------
# Export
# ---------------------------------------------------------------------------

class TestExportExceptionHierarchy:
    def test_export_error_is_weissman_error(self):
        assert issubclass(ExportError, WeissmanError)

    def test_pdf_generation_is_export_error(self):
        assert issubclass(PDFGenerationError, ExportError)

    def test_sanitization_is_export_error(self):
        assert issubclass(SanitizationError, ExportError)


# ---------------------------------------------------------------------------
# Feed
# ---------------------------------------------------------------------------

class TestFeedExceptionHierarchy:
    def test_feed_error_is_weissman_error(self):
        assert issubclass(FeedError, WeissmanError)

    def test_feed_timeout_is_feed_error(self):
        assert issubclass(FeedTimeoutError, FeedError)

    def test_feed_parse_is_feed_error(self):
        assert issubclass(FeedParseError, FeedError)

    def test_raise_feed_timeout(self):
        with pytest.raises(FeedError):
            raise FeedTimeoutError("NVD timed out", feed="nvd")


# ---------------------------------------------------------------------------
# Webhook
# ---------------------------------------------------------------------------

class TestWebhookExceptionHierarchy:
    def test_webhook_error_is_weissman_error(self):
        assert issubclass(WebhookError, WeissmanError)

    def test_webhook_delivery_is_webhook_error(self):
        assert issubclass(WebhookDeliveryError, WebhookError)

    def test_webhook_validation_is_webhook_error(self):
        assert issubclass(WebhookValidationError, WebhookError)


# ---------------------------------------------------------------------------
# Other standalone exceptions
# ---------------------------------------------------------------------------

class TestMiscExceptions:
    def test_configuration_error_is_weissman_error(self):
        assert issubclass(ConfigurationError, WeissmanError)

    def test_cache_error_is_weissman_error(self):
        assert issubclass(CacheError, WeissmanError)

    def test_redis_connection_is_cache_error(self):
        assert issubclass(RedisConnectionError, CacheError)

    def test_validation_error_is_weissman_error(self):
        assert issubclass(ValidationError, WeissmanError)

    def test_invalid_input_is_validation_error(self):
        assert issubclass(InvalidInputError, ValidationError)


# ---------------------------------------------------------------------------
# HTTP_EXCEPTION_MAP
# ---------------------------------------------------------------------------

class TestHTTPExceptionMap:
    """Tests for the HTTP status code to exception mapping."""

    def test_map_contains_401(self):
        assert 401 in HTTP_EXCEPTION_MAP
        assert HTTP_EXCEPTION_MAP[401] is InvalidCredentialsError

    def test_map_contains_403(self):
        assert 403 in HTTP_EXCEPTION_MAP
        assert HTTP_EXCEPTION_MAP[403] is AuthorizationError

    def test_map_contains_404(self):
        assert 404 in HTTP_EXCEPTION_MAP
        assert HTTP_EXCEPTION_MAP[404] is VulnerabilityNotFoundError

    def test_map_contains_429(self):
        assert 429 in HTTP_EXCEPTION_MAP
        assert HTTP_EXCEPTION_MAP[429] is RateLimitExceeded

    def test_map_values_are_weissman_error_subclasses(self):
        for status_code, exc_class in HTTP_EXCEPTION_MAP.items():
            assert issubclass(exc_class, WeissmanError), (
                f"HTTP_EXCEPTION_MAP[{status_code}] = {exc_class.__name__} "
                f"is not a WeissmanError subclass"
            )

    def test_map_values_are_instantiable(self):
        for status_code, exc_class in HTTP_EXCEPTION_MAP.items():
            exc = exc_class(f"HTTP {status_code} error")
            assert isinstance(exc, WeissmanError)
