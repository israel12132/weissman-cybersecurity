//! Cryptographic provenance for Command Center forensic UI.
//!
//! Shared verbatim between:
//! - `fingerprint_engine` (signs `/api/engines/capabilities` manifests)
//! - Browser WASM (`verify_*` exports for zero-trust badge rendering)

mod belief;
mod manifest;
mod telemetry;

pub use belief::{
    collapse_belief, log_odds_fusion, noisy_or_belief, risk_to_belief, temporal_decay, FusionMode,
};
pub use manifest::{sign_capabilities_manifest, verify_capabilities_manifest, ProvenanceManifest};
pub use telemetry::{verify_telemetry_event, TelemetryVerifyResult, VerifyStatus};

#[cfg(feature = "wasm")]
mod wasm_exports;
