//! Provider adapter traits — core engine routes generic commands here.

use async_trait::async_trait;
use serde_json::Value;
use sqlx::PgPool;

use super::integrations::IntegrationRecord;
use super::types::{AdapterOutcome, ExecuteActionCommand, RevertStep, VerifyProbeSpec};

#[derive(Debug, thiserror::Error)]
pub enum AdapterError {
    #[error("configuration: {0}")]
    Config(String),
    #[error("provider API: {0}")]
    Provider(String),
    #[error("skipped: {0}")]
    Skipped(String),
}

pub struct AdapterContext<'a> {
    pub pool: &'a PgPool,
    pub cmd: &'a ExecuteActionCommand,
    pub integration: &'a IntegrationRecord,
}

/// All live SOAR provider adapters (8+).
pub const REGISTERED_ADAPTER_IDS: &[&str] = &[
    "aws_ec2",
    "azure_vm",
    "crowdstrike_falcon",
    "github",
    "pagerduty",
    "opsgenie",
    "slack",
    "servicenow",
];

#[must_use]
pub fn registered_adapter_count() -> usize {
    REGISTERED_ADAPTER_IDS.len()
}

/// Host isolation — AWS EC2, Azure VM, CrowdStrike Falcon.
#[async_trait]
pub trait IsolateHostAdapter: Send + Sync {
    fn provider_id(&self) -> &'static str;
    async fn isolate(&self, ctx: &AdapterContext<'_>) -> Result<AdapterOutcome, AdapterError>;
    async fn verify_isolated(
        &self,
        target: &str,
        ports: &[u16],
        payload: &Value,
    ) -> Result<bool, AdapterError>;
    fn revert_steps(&self, outcome: &AdapterOutcome) -> Vec<RevertStep>;
}

/// Pull-request remediation — GitHub/GitLab via auto-heal pipeline.
#[async_trait]
pub trait OpenPullRequestAdapter: Send + Sync {
    fn provider_id(&self) -> &'static str;
    async fn open_pr(&self, ctx: &AdapterContext<'_>) -> Result<AdapterOutcome, AdapterError>;
    async fn verify_pr(&self, external_ref: &str, payload: &Value) -> Result<bool, AdapterError>;
    fn revert_steps(&self, outcome: &AdapterOutcome) -> Vec<RevertStep>;
}

/// On-call paging — PagerDuty / OpsGenie.
#[async_trait]
pub trait PageOncallAdapter: Send + Sync {
    fn provider_id(&self) -> &'static str;
    async fn page(&self, ctx: &AdapterContext<'_>) -> Result<AdapterOutcome, AdapterError>;
    async fn verify_delivery(
        &self,
        external_ref: &str,
        payload: &Value,
    ) -> Result<bool, AdapterError>;
    fn revert_steps(&self, outcome: &AdapterOutcome) -> Vec<RevertStep>;
}

pub mod aws_ec2;
pub mod azure_vm;
pub mod common;
pub mod crowdstrike_falcon;
pub mod github;
pub mod opsgenie;
pub mod pagerduty;
pub mod servicenow;
pub mod slack;

use aws_ec2::AwsEc2IsolateAdapter;
use azure_vm::AzureVmIsolateAdapter;
use crowdstrike_falcon::CrowdStrikeFalconAdapter;
use github::GithubPrAdapter;
use opsgenie::OpsGenieAdapter;
use pagerduty::PagerDutyAdapter;
use servicenow::{CreateIncidentAdapter, ServiceNowAdapter};
use slack::{SlackAdapter, SlackNotifyAdapter};

fn normalize_provider(provider: &str) -> String {
    provider.trim().to_ascii_lowercase().replace('-', "_")
}

async fn dispatch_isolate(
    provider: &str,
    ctx: &AdapterContext<'_>,
) -> Result<AdapterOutcome, AdapterError> {
    match normalize_provider(provider).as_str() {
        "aws" | "aws_ec2" | "ec2" => AwsEc2IsolateAdapter.isolate(ctx).await,
        "azure" | "azure_vm" | "azure_defender" => AzureVmIsolateAdapter.isolate(ctx).await,
        "crowdstrike" | "crowdstrike_falcon" | "falcon" => {
            CrowdStrikeFalconAdapter.isolate(ctx).await
        }
        other => Err(AdapterError::Config(format!(
            "no isolate adapter for provider {other}"
        ))),
    }
}

async fn dispatch_page(
    provider: &str,
    ctx: &AdapterContext<'_>,
) -> Result<AdapterOutcome, AdapterError> {
    match normalize_provider(provider).as_str() {
        "pagerduty" => PagerDutyAdapter.page(ctx).await,
        "opsgenie" => OpsGenieAdapter.page(ctx).await,
        other => Err(AdapterError::Config(format!(
            "no page_oncall adapter for provider {other}"
        ))),
    }
}

/// Route `ExecuteActionCommand` to the correct provider adapter.
pub async fn dispatch(
    cmd: &ExecuteActionCommand,
    pool: &PgPool,
    integration: &IntegrationRecord,
) -> Result<AdapterOutcome, AdapterError> {
    let ctx = AdapterContext {
        pool,
        cmd,
        integration,
    };
    let kind = cmd.action_kind.to_ascii_lowercase();
    let provider = integration.provider_type.as_str();
    match kind.as_str() {
        "isolate_host" => dispatch_isolate(provider, &ctx).await,
        "open_pr" => GithubPrAdapter.open_pr(&ctx).await,
        "page_oncall" => dispatch_page(provider, &ctx).await,
        "slack_notify" => SlackAdapter.notify(&ctx).await,
        "create_incident" => ServiceNowAdapter.create_incident(&ctx).await,
        other => Err(AdapterError::Skipped(format!("no adapter for {other}"))),
    }
}

/// Closed-loop verification via the same adapter family.
pub async fn verify_probe(
    probe_type: &str,
    target: &str,
    ports: &[u16],
    payload: &Value,
    provider: &str,
) -> Result<bool, AdapterError> {
    let p = normalize_provider(provider);
    match probe_type {
        "tcp_unreachable" | "isolate_host" => match p.as_str() {
            "aws_ec2" | "aws" | "ec2" => {
                AwsEc2IsolateAdapter
                    .verify_isolated(target, ports, payload)
                    .await
            }
            "azure_vm" | "azure" => {
                AzureVmIsolateAdapter
                    .verify_isolated(target, ports, payload)
                    .await
            }
            "crowdstrike_falcon" | "crowdstrike" | "falcon" => {
                CrowdStrikeFalconAdapter
                    .verify_isolated(target, ports, payload)
                    .await
            }
            _ => {
                AwsEc2IsolateAdapter
                    .verify_isolated(target, ports, payload)
                    .await
            }
        },
        "pr_exists" | "open_pr" => GithubPrAdapter.verify_pr(target, payload).await,
        "page_ack" | "page_oncall" => match p.as_str() {
            "opsgenie" => OpsGenieAdapter.verify_delivery(target, payload).await,
            _ => PagerDutyAdapter.verify_delivery(target, payload).await,
        },
        "incident_exists" | "create_incident" => {
            ServiceNowAdapter.verify_incident(target, payload).await
        }
        other => Err(AdapterError::Config(format!("unknown probe type {other}"))),
    }
}

#[must_use]
pub fn default_verify_ports() -> Vec<u16> {
    vec![22, 80, 443, 3389]
}

#[must_use]
pub fn probe_from_outcome(
    outcome: &AdapterOutcome,
    cmd: &ExecuteActionCommand,
) -> Option<VerifyProbeSpec> {
    if let Some(p) = outcome.verify_probe.clone() {
        return Some(p);
    }
    match cmd.action_kind.to_ascii_lowercase().as_str() {
        "isolate_host" => Some(VerifyProbeSpec {
            probe_type: "tcp_unreachable".into(),
            target: cmd.target_id.clone(),
            expect_unreachable: true,
            ports: default_verify_ports(),
        }),
        "open_pr" => outcome.external_ref.as_ref().map(|r| VerifyProbeSpec {
            probe_type: "pr_exists".into(),
            target: r.clone(),
            expect_unreachable: false,
            ports: vec![],
        }),
        "page_oncall" => outcome.external_ref.as_ref().map(|r| VerifyProbeSpec {
            probe_type: "page_ack".into(),
            target: r.clone(),
            expect_unreachable: false,
            ports: vec![],
        }),
        "create_incident" => outcome.external_ref.as_ref().map(|r| VerifyProbeSpec {
            probe_type: "incident_exists".into(),
            target: r.clone(),
            expect_unreachable: false,
            ports: vec![],
        }),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn eight_adapters_registered() {
        assert!(registered_adapter_count() >= 8);
        assert!(REGISTERED_ADAPTER_IDS.contains(&"opsgenie"));
        assert!(REGISTERED_ADAPTER_IDS.contains(&"slack"));
        assert!(REGISTERED_ADAPTER_IDS.contains(&"servicenow"));
        assert!(REGISTERED_ADAPTER_IDS.contains(&"azure_vm"));
        assert!(REGISTERED_ADAPTER_IDS.contains(&"crowdstrike_falcon"));
    }
}
