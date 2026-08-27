// Intelligence-grade stealth persistence & defense-evasion control plane.

#[derive(Deserialize)]
struct StealthEvasionQuery {
    client_id: Option<i64>,
}

#[derive(Deserialize)]
struct StealthEvasionFailSafeBody {
    client_id: Option<i64>,
    reason: Option<String>,
}

async fn api_stealthy_persistence_catalog(Extension(_auth): Extension<AuthContext>) -> Response {
    Json(crate::stealthy_persistence_evasion::catalog_json()).into_response()
}

async fn api_stealthy_persistence_status(
    State(state): State<Arc<AppState>>,
    Extension(auth): Extension<AuthContext>,
    Query(q): Query<StealthEvasionQuery>,
) -> Response {
    let mut cp = crate::stealthy_persistence_evasion::control_plane::filesystem_ci_snapshot();
    cp = crate::stealthy_persistence_evasion::control_plane::probe_db(
        &state.app_pool,
        auth.tenant_id,
        q.client_id,
        cp,
    )
    .await;
    let host = crate::stealthy_persistence_evasion::host::collect_live();
    let online = state.endpoint_agents.online_agents().await.len();
    let recent = if let Some(cid) = q.client_id {
        weissman_db::bulk_copy::latest_results(&state.app_pool, auth.tenant_id, cid, 40)
            .await
            .unwrap_or_default()
    } else {
        Vec::new()
    };
    Json(json!({
        "engine": crate::stealthy_persistence_evasion::catalog::ENGINE_ID,
        "catalog_len": crate::stealthy_persistence_evasion::catalog::CATALOG_LEN,
        "host": host,
        "control_plane": cp,
        "online_agents": online,
        "recent_results": recent,
        "mode": "assessment_only",
    }))
    .into_response()
}

async fn api_stealthy_persistence_fail_safe(
    State(state): State<Arc<AppState>>,
    Extension(auth): Extension<AuthContext>,
    Json(body): Json<StealthEvasionFailSafeBody>,
) -> Response {
    let local = crate::stealthy_persistence_evasion::fail_safe_wipe();
    let reason = body
        .reason
        .unwrap_or_else(|| "command-center fail-safe".into());
    let mut agents_signaled = 0u32;
    if let Some(cid) = body.client_id {
        if let Ok(uuids) = crate::endpoint_agents::agent_uuids_for_client(
            &state.app_pool,
            auth.tenant_id,
            cid,
            crate::endpoint_agents::FLEET_MAX_AGENTS,
        )
        .await
        {
            for uuid in uuids {
                if state
                    .endpoint_agents
                    .send(
                        &uuid,
                        crate::endpoint_agents::ServerToAgent::FailSafeWipe {
                            reason: reason.clone(),
                        },
                    )
                    .await
                    .is_ok()
                {
                    agents_signaled += 1;
                }
            }
        }
    }
    Json(json!({
        "ok": true,
        "local": local,
        "agents_signaled": agents_signaled,
        "reason": reason,
        "note": "Weissman canaries + agent ring-buffer only. EDR/ETW/AMSI/OS persistence untouched.",
    }))
    .into_response()
}
