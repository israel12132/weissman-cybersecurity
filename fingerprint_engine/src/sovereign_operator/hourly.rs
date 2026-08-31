//! Hourly log auditor + aggression re-dispatch (standing, owner-plane, RoE safe_proofs).

use serde_json::json;
use sqlx::PgPool;
use std::sync::Arc;
use tokio::sync::broadcast::Sender;

pub fn spawn_hourly_loop(app_pool: Arc<PgPool>, telemetry: Arc<Sender<String>>) {
    let interval_secs = std::env::var("WEISSMAN_SOVEREIGN_HOURLY_SECS")
        .ok()
        .and_then(|s| s.parse::<u64>().ok())
        .unwrap_or(3600)
        .max(300);
    tokio::spawn(async move {
        let mut tick = tokio::time::interval(std::time::Duration::from_secs(interval_secs));
        tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        tick.tick().await;
        loop {
            tick.tick().await;
            let tenants = match weissman_db::active_tenant_ids(app_pool.as_ref()).await {
                Ok(t) => t,
                Err(e) => {
                    tracing::warn!(target: "sovereign_operator", error = %e, "tenant enumeration failed");
                    continue;
                }
            };
            for tenant_id in tenants {
                match crate::sovereign_operator::tools::hourly_tune_cycle(
                    app_pool.as_ref(),
                    tenant_id,
                )
                .await
                {
                    Ok(summary) => {
                        let n = summary
                            .get("tuned_jobs")
                            .and_then(|v| v.as_array())
                            .map(|a| a.len())
                            .unwrap_or(0);
                        tracing::info!(
                            target: "sovereign_operator",
                            tenant_id,
                            tuned = n,
                            "hourly engine-log audit complete"
                        );
                        let wire = crate::http::tenant_stream::stamp_value(
                            tenant_id,
                            json!({
                                "type": "sovereign_hourly_audit",
                                "summary": summary,
                            }),
                        );
                        let _ = telemetry.send(wire.clone());
                        crate::telemetry_bus::publish_bus("telemetry", &wire).await;
                    }
                    Err(e) => {
                        tracing::warn!(target: "sovereign_operator", tenant_id, error = %e, "hourly cycle failed");
                    }
                }
            }
        }
    });
}
