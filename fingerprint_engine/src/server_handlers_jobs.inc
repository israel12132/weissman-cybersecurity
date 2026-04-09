/// Unified async job + PoE job status (tenant-scoped).
async fn api_async_job_status(
    State(state): State<Arc<AppState>>,
    Extension(auth): Extension<AuthContext>,
    Path(job_id): Path<uuid::Uuid>,
) -> Response {
    match db::job_queue::get_job_for_tenant(state.app_pool.as_ref(), auth.tenant_id, job_id).await {
        Ok(Some(status)) => {
            return (StatusCode::OK, Json(json!(status))).into_response();
        }
        Err(e) => {
            tracing::error!(target: "async_jobs", error = %e, "get_job_for_tenant failed");
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": "database_error", "detail": e.to_string()})),
            )
                .into_response();
        }
        Ok(None) => {}
    }
    let Ok(mut tx) = db::begin_tenant_tx(&state.app_pool, auth.tenant_id).await else {
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(json!({"error": "database_unavailable"})),
        )
            .into_response();
    };
    let jid = job_id.to_string();
    let row = sqlx::query(
        r#"SELECT job_id, status, run_id, message, error, COALESCE(findings_json,'[]') AS findings_json
           FROM poe_jobs WHERE job_id = $1"#,
    )
    .bind(&jid)
    .fetch_optional(&mut *tx)
    .await;
    let _ = tx.commit().await;
    match row {
        Ok(Some(r)) => {
            let findings_json: String = r.try_get("findings_json").unwrap_or_else(|_| "[]".into());
            let findings_count = serde_json::from_str::<Vec<Value>>(&findings_json)
                .map(|v| v.len())
                .unwrap_or(0);
            (
                StatusCode::OK,
                Json(json!({
                    "source": "poe_job",
                    "id": jid,
                    "status": r.try_get::<String,_>("status").unwrap_or_default(),
                    "run_id": r.try_get::<Option<i64>,_>("run_id").ok().flatten(),
                    "message": r.try_get::<Option<String>,_>("message").ok().flatten(),
                    "error": r.try_get::<Option<String>,_>("error").ok().flatten(),
                    "findings_count": findings_count,
                })),
            )
                .into_response()
        }
        Ok(None) => (
            StatusCode::NOT_FOUND,
            Json(json!({"error": "job_not_found"})),
        )
            .into_response(),
        Err(e) => {
            tracing::error!(target: "async_jobs", error = %e, "poe_jobs lookup failed");
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": "database_error", "detail": e.to_string()})),
            )
                .into_response()
        }
    }
}
