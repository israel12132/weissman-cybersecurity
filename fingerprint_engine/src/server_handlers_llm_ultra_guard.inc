// LLM Ultra-Guard APIs — live inspect + event/RAG integrity dashboards.

#[derive(serde::Deserialize)]
struct LlmGuardInspectBody {
    prompt: String,
    #[serde(default)]
    history: Vec<String>,
    #[serde(default)]
    financial_risk_high: bool,
}

async fn api_llm_ultra_guard_inspect(
    State(state): State<Arc<AppState>>,
    Extension(auth): Extension<AuthContext>,
    Json(body): Json<LlmGuardInspectBody>,
) -> Response {
    if let Err(r) = crate::rbac::require_analyst(&auth) {
        return r;
    }
    let prompt = body.prompt.trim();
    if prompt.is_empty() {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({"ok": false, "detail": "prompt is required"})),
        )
            .into_response();
    }
    let ctx = crate::llm_ultra_guard::GuardContext {
        tenant_id: Some(auth.tenant_id),
        user_id: Some(auth.user_id),
        source: "inspect",
        history: body.history,
        financial_risk_high: body.financial_risk_high,
        ..crate::llm_ultra_guard::GuardContext::default()
    };
    let report = crate::llm_ultra_guard::inspect_prompt(prompt, &ctx);
    let event_id = crate::llm_ultra_guard::persist_event(
        &state.app_pool,
        &ctx,
        "prompt_injection_brake",
        &report,
    )
    .await
    .ok()
    .flatten();
    (
        StatusCode::OK,
        Json(json!({
            "ok": true,
            "event_id": event_id,
            "report": report.to_json(),
            "metrics": crate::llm_ultra_guard::runtime_metrics(),
        })),
    )
        .into_response()
}

async fn api_llm_ultra_guard_status(
    State(state): State<Arc<AppState>>,
    Extension(auth): Extension<AuthContext>,
) -> Response {
    let events = crate::llm_ultra_guard::list_recent_events(&state.app_pool, auth.tenant_id, 25)
        .await
        .unwrap_or_default();
    (
        StatusCode::OK,
        Json(json!({
            "ok": true,
            "metrics": crate::llm_ultra_guard::runtime_metrics(),
            "tuning": crate::llm_ultra_guard::tuning::as_json(),
            "events": events,
            "engines": [
                crate::llm_ultra_guard::ENGINE_PROMPT_INJECTION,
                crate::llm_ultra_guard::ENGINE_JAILBREAK,
                crate::llm_ultra_guard::ENGINE_RAG_GUARD,
            ],
        })),
    )
        .into_response()
}

async fn api_llm_ultra_guard_events(
    State(state): State<Arc<AppState>>,
    Extension(auth): Extension<AuthContext>,
    Query(q): Query<std::collections::HashMap<String, String>>,
) -> Response {
    let limit: i64 = q
        .get("limit")
        .and_then(|s| s.parse().ok())
        .unwrap_or(50)
        .clamp(1, 200);
    match crate::llm_ultra_guard::list_recent_events(&state.app_pool, auth.tenant_id, limit).await {
        Ok(events) => (StatusCode::OK, Json(json!({"ok": true, "events": events}))).into_response(),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({"ok": false, "detail": e})),
        )
            .into_response(),
    }
}

async fn api_llm_ultra_guard_rag(
    State(state): State<Arc<AppState>>,
    Extension(auth): Extension<AuthContext>,
) -> Response {
    match crate::llm_ultra_guard::rag_integrity_snapshot(&state.app_pool, auth.tenant_id).await {
        Ok(snap) => (StatusCode::OK, Json(json!({"ok": true, "integrity": snap}))).into_response(),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({"ok": false, "detail": e})),
        )
            .into_response(),
    }
}
