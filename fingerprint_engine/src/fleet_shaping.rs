//! Global fleet traffic shaping — wires `weissman-fleet-shaping` into live engine probes.
//!
//! Workers call [`install_global`] at boot. Job execution sets [`ProbeScope`] via task-local
//! so every `engine_probes::http_*` call acquires a distributed token before firing.

use std::sync::{Arc, OnceLock};
use weissman_fleet_shaping::{FleetCoordinator, TargetPainSignal};

static GLOBAL: OnceLock<Arc<FleetCoordinator>> = OnceLock::new();

tokio::task_local! {
    static PROBE_SCOPE: ProbeScope;
}

/// Per-task probe context (tenant + optional target override).
#[derive(Debug, Clone, Default)]
pub struct ProbeScope {
    pub tenant_id: Option<i64>,
    pub shaping_enabled: bool,
}

/// Install fleet coordinator (worker boot). Idempotent — first install wins.
pub fn install_global(coordinator: Arc<FleetCoordinator>) {
    let _ = GLOBAL.set(coordinator);
}

#[must_use]
pub fn global() -> Option<Arc<FleetCoordinator>> {
    GLOBAL.get().cloned()
}

#[must_use]
pub fn is_installed() -> bool {
    GLOBAL.get().is_some()
}

/// Run an async closure with probe scope (tenant id from job).
pub async fn with_scope<F, T>(scope: ProbeScope, f: F) -> T
where
    F: std::future::Future<Output = T>,
{
    PROBE_SCOPE.scope(scope, f).await
}

/// Acquire distributed token before an outbound probe (no-op when shaping disabled).
pub async fn acquire_for_url(url: &str) {
    let scope = PROBE_SCOPE.try_with(|s| s.clone()).unwrap_or_default();
    if !scope.shaping_enabled {
        return;
    }
    let Some(tenant_id) = scope.tenant_id else {
        return;
    };
    let Some(coord) = global() else {
        return;
    };
    let host = crate::engine_probes::extract_host(url);
    if host.is_empty() {
        return;
    }
    if let Err(e) = coord.acquire_probe(tenant_id, &host).await {
        tracing::warn!(target: "fleet_shaping", error = %e, host = %host, "probe acquire failed");
    }
}

/// Report target pain after a probe completes.
pub fn report_outcome(url: &str, status: u16, ttfb_ms: Option<u64>, tcp_reset: bool) {
    let scope = PROBE_SCOPE.try_with(|s| s.clone()).unwrap_or_default();
    let Some(tenant_id) = scope.tenant_id else {
        return;
    };
    let Some(coord) = global() else {
        return;
    };
    let host = crate::engine_probes::extract_host(url);
    if host.is_empty() {
        return;
    }
    let signal = TargetPainSignal {
        http_status: Some(status),
        ttfb_ms,
        tcp_reset,
        connection_error: status == 0,
    };
    let coord = coord.clone();
    tokio::spawn(async move {
        coord.report_probe_outcome(tenant_id, &host, signal).await;
    });
}

/// CEO / Command Center fleet telemetry snapshot.
pub async fn telemetry_snapshot(tenant_id: i64) -> serde_json::Value {
    match global() {
        Some(c) => c.snapshot(tenant_id).await,
        None => serde_json::json!({ "enabled": false, "reason": "fleet_shaping_not_installed" }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_scope_disables_shaping() {
        let s = ProbeScope::default();
        assert!(!s.shaping_enabled);
    }
}
