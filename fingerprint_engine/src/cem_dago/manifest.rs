//! Cognitive engine contract: prerequisites (blackboard keys) and output signals.

use super::blackboard::ScanBlackboard;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::sync::Arc;

/// Attack-graph edge families used by the DAG router when matching fallback engines.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EdgeKind {
    WebPort,
    OtProtocol,
    CredentialAccess,
    ActiveDirectoryDomain,
    CloudMetadata,
}

impl EdgeKind {
    #[must_use]
    pub fn signal(self) -> &'static str {
        match self {
            Self::WebPort => "web_port_active",
            Self::OtProtocol => "ot_protocol",
            Self::CredentialAccess => "credential_access",
            Self::ActiveDirectoryDomain => "ad_domain",
            Self::CloudMetadata => "cloud_metadata",
        }
    }

    #[must_use]
    pub fn from_graph_label(label: &str) -> Option<Self> {
        let l = label.to_ascii_lowercase();
        if l.contains("modbus")
            || l.contains("enip")
            || l.contains("s7")
            || l.contains("ot")
            || l.contains("ics")
            || l.contains("plc")
            || l.contains("scada")
        {
            return Some(Self::OtProtocol);
        }
        if l.contains("kerberos")
            || l.contains("ldap")
            || l.contains("ad_")
            || l.contains("active_directory")
            || l.contains("domain")
        {
            return Some(Self::ActiveDirectoryDomain);
        }
        if l.contains("aws")
            || l.contains("azure")
            || l.contains("gcp")
            || l.contains("cloud")
            || l.contains("iam")
        {
            return Some(Self::CloudMetadata);
        }
        if l.contains("auth")
            || l.contains("cred")
            || l.contains("identity")
            || l.contains("token")
            || l.contains("password")
        {
            return Some(Self::CredentialAccess);
        }
        if l.contains("http")
            || l.contains("web")
            || l.contains("exposes")
            || l.contains("leads_to")
            || l.contains("host")
            || l.contains("port")
        {
            return Some(Self::WebPort);
        }
        None
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EngineManifest {
    pub id: String,
    /// Blackboard keys that should be present before launch (soft: skipped if no producer in the scan set).
    pub required_inputs: Vec<String>,
    /// Signals this engine can write after a successful run.
    pub output_signals: Vec<String>,
    pub mitre_techniques: Vec<String>,
    pub edge_kinds: Vec<EdgeKind>,
}

#[async_trait::async_trait]
pub trait CognitiveEngine: Send + Sync {
    fn manifest(&self) -> EngineManifest;

    async fn run(
        &self,
        target: &str,
        blackboard: Arc<ScanBlackboard>,
    ) -> Result<Vec<Value>, String>;
}
