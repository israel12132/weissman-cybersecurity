//! Reusable OpenAPI fragment for composing server documentation (`utoipa`).
//!
//! Merge into the server crate with `#[derive(OpenApi)]` and `components(schemas_from(...))`
//! pointing at this struct, or by copying the `components(schemas(...))` list into your API doc.

use utoipa::OpenApi;

use crate::errors::{ErrorBody, ErrorCode};
use crate::models::config::ClientConfigSnapshot;
use crate::models::engine::EngineId;
use crate::models::finding::Severity;
use crate::models::ids::{ClientId, FindingId, JobId, RunId, TenantId};
use crate::models::roe::RoeMode;
use crate::models::semantic::{SemanticConfig, StateEdge, StateNode};

/// Core DTOs and error shapes for OpenAPI composition.
#[derive(OpenApi)]
#[openapi(
    components(schemas(
        ErrorBody,
        ErrorCode,
        Severity,
        RoeMode,
        EngineId,
        ClientConfigSnapshot,
        SemanticConfig,
        StateNode,
        StateEdge,
        TenantId,
        ClientId,
        RunId,
        FindingId,
        JobId,
    ))
)]
pub struct WeissmanCoreApi;
