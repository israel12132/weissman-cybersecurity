"""
src/exceptions.py
=================
Structured exception hierarchy for Weissman Cybersecurity platform.

Usage:
    from src.exceptions import RateLimitExceeded, InvalidPasswordError

    raise RateLimitExceeded("Too many requests", tenant_id="tenant123")
"""


class WeissmanError(Exception):
    """Base exception for all Weissman errors."""

    def __init__(self, message: str, **context):
        super().__init__(message)
        self.message = message
        self.context = context

    def __str__(self) -> str:
        if self.context:
            ctx = ", ".join(f"{k}={v}" for k, v in self.context.items())
            return f"{self.message} ({ctx})"
        return self.message


# Authentication & Authorization Errors
class AuthenticationError(WeissmanError):
    """Base class for authentication failures."""
    pass


class InvalidCredentialsError(AuthenticationError):
    """Username/password combination is invalid."""
    pass


class MFARequiredError(AuthenticationError):
    """MFA verification is required."""
    pass


class MFAInvalidError(AuthenticationError):
    """MFA token is invalid or expired."""
    pass


class AuthorizationError(WeissmanError):
    """User does not have permission to perform this action."""
    pass


class InsufficientRoleError(AuthorizationError):
    """User's role does not meet minimum requirements."""
    pass


# Password & Security Errors
class InvalidPasswordError(WeissmanError):
    """Password does not meet security policy requirements."""
    pass


class RateLimitExceeded(WeissmanError):
    """Rate limit has been exceeded for this tenant/IP."""
    pass


# Scanning & Engine Errors
class ScanError(WeissmanError):
    """Base class for scanning engine errors."""
    pass


class InvalidTargetError(ScanError):
    """Target URL or domain is invalid."""
    pass


class ScanTimeoutError(ScanError):
    """Scan operation timed out."""
    pass


class EngineError(ScanError):
    """Scanning engine encountered an error."""
    pass


# Database & Data Errors
class DatabaseError(WeissmanError):
    """Base class for database-related errors."""
    pass


class TenantNotFoundError(DatabaseError):
    """Requested tenant does not exist."""
    pass


class VulnerabilityNotFoundError(DatabaseError):
    """Requested vulnerability does not exist."""
    pass


# PDF & Export Errors
class ExportError(WeissmanError):
    """Base class for export/reporting errors."""
    pass


class PDFGenerationError(ExportError):
    """Failed to generate PDF report."""
    pass


class SanitizationError(ExportError):
    """Failed to sanitize HTML content."""
    pass


# Feed & Integration Errors
class FeedError(WeissmanError):
    """Base class for threat feed errors."""
    pass


class FeedTimeoutError(FeedError):
    """Threat feed request timed out."""
    pass


class FeedParseError(FeedError):
    """Failed to parse threat feed response."""
    pass


# Webhook & Notification Errors
class WebhookError(WeissmanError):
    """Base class for webhook delivery errors."""
    pass


class WebhookDeliveryError(WebhookError):
    """Failed to deliver webhook notification."""
    pass


class WebhookValidationError(WebhookError):
    """Webhook signature validation failed."""
    pass


# Configuration Errors
class ConfigurationError(WeissmanError):
    """Invalid configuration or missing required settings."""
    pass


# Redis & Cache Errors
class CacheError(WeissmanError):
    """Base class for caching errors."""
    pass


class RedisConnectionError(CacheError):
    """Failed to connect to Redis."""
    pass


# Validation Errors
class ValidationError(WeissmanError):
    """Input validation failed."""
    pass


class InvalidInputError(ValidationError):
    """User input is invalid or malformed."""
    pass


# Map common HTTP status codes to exceptions
HTTP_EXCEPTION_MAP = {
    401: InvalidCredentialsError,
    403: AuthorizationError,
    404: VulnerabilityNotFoundError,
    429: RateLimitExceeded,
}
