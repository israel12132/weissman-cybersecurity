// GET /api/analytics/attack-vectors — evidence-gated cross-domain fusion.

async fn api_analytics_attack_vectors(
    State(state): State<Arc<AppState>>,
    Extension(auth): Extension<AuthContext>,
) -> Response {
    let Ok(mut tx) = db::begin_tenant_tx(&state.app_pool, auth.tenant_id).await else {
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(json!({ "ok": false, "detail": "database unavailable" })),
        )
            .into_response();
    };
    let rows = sqlx::query(
        r#"SELECT id, COALESCE(source, '') AS engine, COALESCE(severity, 'info') AS severity,
                  COALESCE(title, '') AS title, COALESCE(description, '') AS description,
                  client_id
             FROM vulnerabilities
            WHERE tenant_id = $1
              AND COALESCE(status, 'OPEN') NOT IN ('FIXED', 'FALSE_POSITIVE', 'VERIFIED_FIXED')
            ORDER BY created_at DESC
            LIMIT 2000"#,
    )
    .bind(auth.tenant_id)
    .fetch_all(&mut *tx)
    .await
    .unwrap_or_default();
    let _ = tx.commit().await;

    let findings: Vec<crate::attack_vector_synthesis::FindingLite> = rows
        .into_iter()
        .map(|r| crate::attack_vector_synthesis::FindingLite {
            id: r.try_get::<i64, _>("id").unwrap_or(0).to_string(),
            engine: r.try_get::<String, _>("engine").unwrap_or_default(),
            severity: r.try_get::<String, _>("severity").unwrap_or_else(|_| "info".into()),
            title: r.try_get::<String, _>("title").unwrap_or_default(),
            description: r.try_get::<String, _>("description").unwrap_or_default(),
            client_id: r.try_get::<Option<i64>, _>("client_id").ok().flatten(),
        })
        .collect();
    (StatusCode::OK, Json(crate::attack_vector_synthesis::synthesize_json(&findings))).into_response()
}
