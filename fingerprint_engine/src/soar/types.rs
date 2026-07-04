//! Core SOAR execution types — provider-agnostic command envelope.

use serde::{Deserialize, Serialize};
use serde_json::Value;
use uuid::Uuid;

use crate::soar_playbook::PlaybookEvent;

/// Lifecycle status for a durable SOAR execution row.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ExecutionStatus {
    Queued,
    Acquired,
    Executing,
    Verifying,
    Resolved,
    Failed,
    BlockedBlastRadius,
    DuplicateSkipped,
}

impl ExecutionStatus {
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Queued => "queued",
            Self::Acquired => "acquired",
            Self::Executing => "executing",
            Self::Verifying => "verifying",
            Self::Resolved => "resolved",
            Self::Failed => "failed",
            Self::BlockedBlastRadius => "blocked_blast_radius",
            Self::DuplicateSkipped => "duplicate_skipped",
        }
    }

    #[must_use]
    pub fn is_terminal(self) -> bool {
        matches!(
            self,
            Self::Resolved | Self::Failed | Self::BlockedBlastRadius | Self::DuplicateSkipped
        )
    }
}

/// Mathematical proof bundle attached to every autonomous decision.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThreatEvidence {
    pub finding_id: Option<i64>,
    pub title: String,
    pub severity: String,
    pub source: String,
    pub target: String,
    pub cve: Option<String>,
    pub signature_hash: Option<String>,
    pub cvss: Option<f32>,
    pub epss: Option<f32>,
    pub kev: bool,
    pub internet_exposed: bool,
    pub trigger_kind: String,
}

impl ThreatEvidence {
    #[must_use]
    pub fn from_playbook_event(ev: &PlaybookEvent) -> Self {
        Self {
            finding_id: ev.finding_id,
            title: ev.title.clone(),
            severity: ev.severity.clone(),
            source: ev.source.clone(),
            target: ev.target.clone(),
            cve: ev.cve.clone(),
            signature_hash: ev.signature_hash.clone(),
            cvss: ev.cvss,
            epss: ev.epss,
            kev: ev.kev,
            internet_exposed: ev.internet_exposed,
            trigger_kind: ev.kind.clone(),
        }
    }

    #[must_use]
    pub fn vulnerability_signature(&self) -> String {
        self.signature_hash
            .clone()
            .or_else(|| self.cve.clone())
            .unwrap_or_else(|| format!("{}|{}", self.source, self.title))
    }
}

/// Generic command emitted by the playbook engine — routed to provider adapters.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExecuteActionCommand {
    pub action_kind: String,
    pub tenant_id: i64,
    pub client_id: Option<i64>,
    pub playbook_id: Option<i64>,
    pub target_id: String,
    pub params: Value,
    pub evidence: ThreatEvidence,
    pub dry_run: bool,
}

/// Blast-radius evaluation output stored on the execution row.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct BlastRadiusReport {
    pub target_asset_value_usd: i64,
    pub neighbor_asset_value_usd: i64,
    pub crown_jewel_touched: bool,
    pub neighbor_count: u32,
    pub vpc_tag_mismatch: bool,
    pub blocked: bool,
    pub block_reason: String,
}

/// Result returned to the playbook dispatcher.
#[derive(Debug, Clone)]
pub struct ActionOutcome {
    pub status: String,
    pub detail: String,
    pub execution_id: Option<Uuid>,
}

/// One reversible step in an auto-revert runbook.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RevertStep {
    pub provider: String,
    pub operation: String,
    pub payload: Value,
    pub description: String,
}

/// Adapter execution result — includes external refs for verification/revert.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AdapterOutcome {
    pub provider: String,
    pub external_ref: Option<String>,
    pub detail: String,
    pub payload: Value,
    pub revert_steps: Vec<RevertStep>,
    pub verify_probe: Option<VerifyProbeSpec>,
}

/// Specification for a closed-loop verification probe.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VerifyProbeSpec {
    pub probe_type: String,
    pub target: String,
    pub expect_unreachable: bool,
    pub ports: Vec<u16>,
}
