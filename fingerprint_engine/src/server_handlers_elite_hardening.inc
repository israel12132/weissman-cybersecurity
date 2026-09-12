async fn api_elite_hardening_status(Extension(_auth): Extension<AuthContext>) -> Response {
    (
        StatusCode::OK,
        Json(crate::elite_hardening::status_snapshot()),
    )
        .into_response()
}

/// GET /api/market-readiness — catalog-honest GTM snapshot + live finding counts.
async fn api_market_readiness(
    State(state): State<Arc<AppState>>,
    Extension(auth): Extension<AuthContext>,
    Query(q): Query<std::collections::HashMap<String, String>>,
) -> Response {
    let mut body = crate::elite_hardening::moat::market_readiness();
    let client_id = q.get("client_id").and_then(|s| s.parse::<i64>().ok());
    match db::begin_tenant_tx(&state.app_pool, auth.tenant_id).await {
        Ok(mut tx) => {
            let rows = if let Some(cid) = client_id {
                sqlx::query(
                    r#"SELECT source, COUNT(*)::bigint AS n
                       FROM vulnerabilities
                       WHERE tenant_id = $1 AND client_id = $2
                         AND source IN (
                           'prevention_fabric_breach_proof',
                           'ngfw_posture',
                           'sase_security_bypass',
                           'waf_bypass',
                           'control_plane_of_controls',
                           'zero_trust_bypass',
                           'weissman_vngfw'
                         )
                       GROUP BY source"#,
                )
                .bind(auth.tenant_id)
                .bind(cid)
                .fetch_all(&mut *tx)
                .await
            } else {
                sqlx::query(
                    r#"SELECT source, COUNT(*)::bigint AS n
                       FROM vulnerabilities
                       WHERE tenant_id = $1
                         AND source IN (
                           'prevention_fabric_breach_proof',
                           'ngfw_posture',
                           'sase_security_bypass',
                           'waf_bypass',
                           'control_plane_of_controls',
                           'zero_trust_bypass',
                           'weissman_vngfw'
                         )
                       GROUP BY source"#,
                )
                .bind(auth.tenant_id)
                .fetch_all(&mut *tx)
                .await
            };
            let _ = tx.commit().await;
            match rows {
                Ok(rows) => {
                    let counts: Vec<Value> = rows
                        .iter()
                        .map(|r| {
                            json!({
                                "source": r.try_get::<String, _>("source").unwrap_or_default(),
                                "count": r.try_get::<i64, _>("n").unwrap_or(0),
                            })
                        })
                        .collect();
                    body["live_findings"] = json!(counts);
                    body["live_findings_scope"] = json!(if client_id.is_some() {
                        "client"
                    } else {
                        "tenant"
                    });
                }
                Err(e) => {
                    body["live_findings"] = Value::Null;
                    body["live_findings_error"] = json!(scrub_internal_error(e));
                }
            }
        }
        Err(_) => {
            body["live_findings"] = Value::Null;
            body["live_findings_error"] = json!("database unavailable");
        }
    }
    (StatusCode::OK, Json(body)).into_response()
}
