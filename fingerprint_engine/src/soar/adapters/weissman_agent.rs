//! Isolate via enrolled Weissman endpoint agent (nftables / Windows firewall).

use async_trait::async_trait;
use serde_json::json;

use super::{AdapterContext, AdapterError, IsolateHostAdapter};
use crate::soar::types::{AdapterOutcome, RevertStep, VerifyProbeSpec};

pub struct WeissmanAgentIsolateAdapter;

#[async_trait]
impl IsolateHostAdapter for WeissmanAgentIsolateAdapter {
    fn provider_id(&self) -> &'static str {
        "weissman_agent"
    }

    async fn isolate(&self, ctx: &AdapterContext<'_>) -> Result<AdapterOutcome, AdapterError> {
        let client_id = ctx.cmd.client_id.ok_or_else(|| {
            AdapterError::Config("weissman_agent isolate requires client_id".into())
        })?;
        if ctx.cmd.dry_run {
            return Ok(AdapterOutcome {
                provider: self.provider_id().into(),
                external_ref: None,
                detail: "dry_run: would dispatch host_isolation to endpoint agent".into(),
                payload: json!({ "client_id": client_id }),
                revert_steps: vec![],
                verify_probe: None,
            });
        }
        let agents = crate::endpoint_agents::AgentRegistry::global();
        let (_, live) = crate::endpoint_agents::enqueue_and_dispatch_fleet(
            ctx.pool,
            &agents,
            ctx.cmd.tenant_id,
            client_id,
            "host_isolation",
            Some(&ctx.cmd.target_id),
            &json!({ "action": "isolate" }),
        )
        .await
        .map_err(|e| AdapterError::Provider(e.to_string()))?;
        if !live {
            return Err(AdapterError::Provider(
                "no enrolled online agent for this client".into(),
            ));
        }
        Ok(AdapterOutcome {
            provider: self.provider_id().into(),
            external_ref: Some(format!("agent-isolate-{client_id}")),
            detail: "host_isolation task dispatched to endpoint agent".into(),
            payload: json!({ "client_id": client_id, "action": "isolate" }),
            revert_steps: vec![RevertStep {
                provider: self.provider_id().into(),
                operation: "release".into(),
                payload: json!({ "client_id": client_id, "action": "release" }),
                description: "Dispatch host_isolation action=release".into(),
            }],
            verify_probe: Some(VerifyProbeSpec {
                probe_type: "isolate_host".into(),
                target: ctx.cmd.target_id.clone(),
                expect_unreachable: true,
                ports: vec![445, 3389],
            }),
        })
    }

    async fn verify_isolated(
        &self,
        target: &str,
        ports: &[u16],
        _payload: &serde_json::Value,
    ) -> Result<bool, AdapterError> {
        let host = crate::engine_probes::extract_host(target);
        for p in ports {
            if crate::engine_probes::tcp_open(&host, *p).await {
                return Ok(false);
            }
        }
        Ok(true)
    }

    fn revert_steps(&self, outcome: &AdapterOutcome) -> Vec<RevertStep> {
        outcome.revert_steps.clone()
    }
}
