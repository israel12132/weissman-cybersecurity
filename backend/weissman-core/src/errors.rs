//! Unified API and domain errors. Client-visible messages must never include DB internals or stack traces.
//!
//! Map [`AppError`] to HTTP in `weissman-server` (Axum `IntoResponse`). OpenAPI documents [`ErrorBody`] and [`ErrorCode`].

use serde::Serialize;
use std::fmt;
use utoipa::ToSchema;

/// Machine-stable error codes for clients and observability (no raw SQL or file paths).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, ToSchema)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
#[schema(
    example = "VALIDATION",
    description = "Stable error code enum for clients and metrics"
)]
pub enum ErrorCode {
    Validation,
    NotFound,
    Unauthorized,
    Forbidden,
    Conflict,
    PayloadTooLarge,
    TooManyRequests,
    ServiceUnavailable,
    Internal,
}

impl ErrorCode {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Validation => "VALIDATION",
            Self::NotFound => "NOT_FOUND",
            Self::Unauthorized => "UNAUTHORIZED",
            Self::Forbidden => "FORBIDDEN",
            Self::Conflict => "CONFLICT",
            Self::PayloadTooLarge => "PAYLOAD_TOO_LARGE",
            Self::TooManyRequests => "TOO_MANY_REQUESTS",
            Self::ServiceUnavailable => "SERVICE_UNAVAILABLE",
            Self::Internal => "INTERNAL",
        }
    }
}

/// JSON body for HTTP error responses (safe for external clients).
#[derive(Debug, Clone, Serialize, ToSchema)]
#[schema(example = json!({"code": "VALIDATION", "message": "Invalid request"}))]
pub struct ErrorBody {
    /// Same value as [`ErrorCode::as_str`].
    pub code: &'static str,
    /// Human-readable message; must not leak internal details.
    pub message: String,
}

impl ErrorBody {
    #[must_use]
    pub fn new(code: ErrorCode, message: impl Into<String>) -> Self {
        Self {
            code: code.as_str(),
            message: message.into(),
        }
    }
}

impl From<&AppError> for ErrorBody {
    fn from(e: &AppError) -> Self {
        e.to_body()
    }
}

/// Top-level application error (`thiserror`). Convert to HTTP only in the server crate.
#[derive(Debug, thiserror::Error)]
pub enum AppError {
    #[error("{0}")]
    Validation(String),

    #[error("not found: {resource}")]
    NotFound { resource: &'static str },

    #[error("unauthorized")]
    Unauthorized,

    #[error("forbidden")]
    Forbidden,

    #[error("{0}")]
    Conflict(String),

    #[error("payload too large")]
    PayloadTooLarge,

    #[error("rate limited")]
    TooManyRequests,

    #[error("service unavailable")]
    ServiceUnavailable,

    /// Intentionally vague public message; log details server-side only.
    #[error("internal error")]
    Internal,
}

impl AppError {
    #[must_use]
    pub const fn code(&self) -> ErrorCode {
        match self {
            Self::Validation(_) => ErrorCode::Validation,
            Self::NotFound { .. } => ErrorCode::NotFound,
            Self::Unauthorized => ErrorCode::Unauthorized,
            Self::Forbidden => ErrorCode::Forbidden,
            Self::Conflict(_) => ErrorCode::Conflict,
            Self::PayloadTooLarge => ErrorCode::PayloadTooLarge,
            Self::TooManyRequests => ErrorCode::TooManyRequests,
            Self::ServiceUnavailable => ErrorCode::ServiceUnavailable,
            Self::Internal => ErrorCode::Internal,
        }
    }

    /// Recommended HTTP status (map in Axum).
    #[must_use]
    pub const fn status_u16(&self) -> u16 {
        match self {
            Self::Validation(_) => 400,
            Self::NotFound { .. } => 404,
            Self::Unauthorized => 401,
            Self::Forbidden => 403,
            Self::Conflict(_) => 409,
            Self::PayloadTooLarge => 413,
            Self::TooManyRequests => 429,
            Self::ServiceUnavailable => 503,
            Self::Internal => 500,
        }
    }

    #[must_use]
    pub fn to_body(&self) -> ErrorBody {
        let code = self.code();
        let message = match self {
            AppError::Validation(s) => s.clone(),
            AppError::NotFound { resource } => format!("resource not found: {resource}"),
            AppError::Unauthorized => "authentication required".to_string(),
            AppError::Forbidden => "access denied".to_string(),
            AppError::Conflict(s) => s.clone(),
            AppError::PayloadTooLarge => "request body too large".to_string(),
            AppError::TooManyRequests => "too many requests".to_string(),
            AppError::ServiceUnavailable => "service temporarily unavailable".to_string(),
            AppError::Internal => "an internal error occurred".to_string(),
        };
        ErrorBody::new(code, message)
    }
}

impl fmt::Display for ErrorCode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn internal_error_body_is_safe() {
        let e = AppError::Internal;
        let b = e.to_body();
        assert_eq!(b.code, "INTERNAL");
        assert!(!b.message.to_lowercase().contains("sql"));
        assert!(!b.message.to_lowercase().contains("postgres"));
    }

    #[test]
    fn validation_maps_to_400() {
        let e = AppError::Validation("bad".into());
        assert_eq!(e.status_u16(), 400);
        assert_eq!(e.code().as_str(), "VALIDATION");
    }
}
