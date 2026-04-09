//! Stable identifier newtypes for tenant-scoped resources (DB-safe, JSON-transparent).

use serde::{Deserialize, Serialize};
use std::fmt;
use std::str::FromStr;
use utoipa::ToSchema;

/// Tenant scope for RLS (`app.current_tenant_id`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, ToSchema)]
#[serde(transparent)]
#[schema(value_type = i64, example = 1)]
pub struct TenantId(i64);

impl TenantId {
    #[inline]
    pub const fn new(raw: i64) -> Option<Self> {
        if raw > 0 {
            Some(Self(raw))
        } else {
            None
        }
    }

    #[inline]
    pub const fn get(self) -> i64 {
        self.0
    }
}

impl fmt::Display for TenantId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// Client / target scope within a tenant.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, ToSchema)]
#[serde(transparent)]
#[schema(value_type = i64, example = 42)]
pub struct ClientId(i64);

impl ClientId {
    #[inline]
    pub const fn new(raw: i64) -> Option<Self> {
        if raw > 0 {
            Some(Self(raw))
        } else {
            None
        }
    }

    #[inline]
    pub const fn get(self) -> i64 {
        self.0
    }
}

impl fmt::Display for ClientId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// Scan / report run identifier (`report_runs.id`, orchestration).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, ToSchema)]
#[serde(transparent)]
#[schema(value_type = i64, example = 1001)]
pub struct RunId(i64);

impl RunId {
    #[inline]
    pub const fn new(raw: i64) -> Option<Self> {
        if raw > 0 {
            Some(Self(raw))
        } else {
            None
        }
    }

    #[inline]
    pub const fn get(self) -> i64 {
        self.0
    }
}

impl fmt::Display for RunId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// Opaque finding key as stored in `vulnerabilities.finding_id` (often `source-run-index`).
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize, ToSchema)]
#[serde(transparent)]
#[schema(value_type = String, example = "bola_idor-42-0")]
pub struct FindingId(pub String);

impl FindingId {
    pub fn new(s: impl Into<String>) -> Self {
        Self(s.into())
    }

    pub fn as_str(&self) -> &str {
        self.0.as_str()
    }
}

impl fmt::Display for FindingId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl FromStr for FindingId {
    type Err = std::convert::Infallible;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(Self(s.to_string()))
    }
}

/// Background job id (PoE queue, scan jobs) — typically a UUID string.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize, ToSchema)]
#[serde(transparent)]
#[schema(value_type = String, example = "550e8400-e29b-41d4-a716-446655440000")]
pub struct JobId(pub String);

impl JobId {
    pub fn new(s: impl Into<String>) -> Self {
        Self(s.into())
    }

    pub fn as_str(&self) -> &str {
        self.0.as_str()
    }
}

impl fmt::Display for JobId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tenant_id_rejects_non_positive() {
        assert!(TenantId::new(0).is_none());
        assert!(TenantId::new(-1).is_none());
        assert_eq!(TenantId::new(1).map(TenantId::get), Some(1));
    }

    #[test]
    fn finding_id_roundtrip() {
        let f = FindingId::new("bola_idor-42-0");
        assert_eq!(f.as_str(), "bola_idor-42-0");
    }
}
