//! Shared domain model, stable identifiers, and unified errors for the Weissman Command Center.
//!
//! - HTTP `IntoResponse` mapping lives in `weissman-server`.
//! - OpenAPI: merge [`openapi::WeissmanCoreApi`] into the server crate's `utoipa` document.
//!
#![forbid(unsafe_code)]

pub mod errors;
pub mod models;
pub mod openapi;
pub mod tls_policy;

pub use errors::{AppError, ErrorBody, ErrorCode};
pub use models::ids::{ClientId, FindingId, JobId, RunId, TenantId};
pub use models::{
    config::ClientConfigSnapshot,
    engine::{
        default_enabled_engine_ids, is_known_engine_id, EngineId, KNOWN_ENGINE_IDS,
    },
    finding::Severity,
    finding_metadata::{finding_description, finding_title_and_severity},
    poc::infer_poc_exploit,
    roe::RoeMode,
    semantic::{SemanticConfig, StateEdge, StateNode},
};
