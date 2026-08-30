//! Persist honey-route hits, update Dijkstra edge weights, floor FAIR ARO, dispatch SOAR.

use serde_json::{json, Value};
use sqlx::{PgPool, Row};
use tokio::sync::broadcast::Sender;

use crate::honey_routing::{
    decision_metadata, escalate_confidence, extract_shell_command, fair_aro_floor,
    honey_edge_weight, truncate_body, HoneyDecision, HoneyHit, CONF_ACTIVE, ENGINE_ID,
    SOAR_COOLDOWN_SECS,
};
use crate::risk_graph::{EDGE_LEADS_TO, NODE_ASSET, NODE_NETWORK};

#[derive(Debug, Clone)]
pub struct IngestResult {
    pub session_id: i64,
    pub tenant_id: i64,
    pub client_id: Option<i64>,
    pub confidence: i32,
    pub high_confidence: bool,
    pub lateral_attempt: bool,
}

pub async fn resolve_scope(
    auth_pool: &PgPool,
    app_pool: &PgPool,
    host: &str,
) -> Result<(i64, Option<i64>), String> {
    let tenant_id: i64 = sqlx::query_scalar(
        "SELECT id FROM tenants WHERE slug = 'default' AND active = true LIMIT 1",
    )
    .fetch_optional(auth_pool)
    .await
    .map_err(|e| e.to_string())?
    .ok_or_else(|| "default tenant missing".to_string())?;

    let host_l = host
        .split(':')
        .next()
        .unwrap_or(host)
        .trim()
        .to_ascii_lowercase();
    let mut tx = crate::db::begin_tenant_tx(app_pool, tenant_id)
        .await
        .map_err(|e| e.to_string())?;

    let bound: Option<i64> = if host_l.is_empty() {
        None
    } else {
        sqlx::query_scalar(
            r#"SELECT client_id FROM honey_route_vhost_bindings
                WHERE tenant_id = $1 AND lower(host) = $2 LIMIT 1"#,
        )
        .bind(tenant_id)
        .bind(&host_l)
        .fetch_optional(&mut *tx)
        .await
        .ok()
        .flatten()
    };

    let env_client = std::env::var("WEISSMAN_HONEY_ROUTE_DEFAULT_CLIENT_ID")
        .ok()
        .and_then(|s| s.parse::<i64>().ok())
        .filter(|n| *n > 0);

    let client_id = if bound.is_some() {
        bound
    } else if env_client.is_some() {
        env_client
    } else {
        sqlx::query_scalar("SELECT id FROM clients WHERE tenant_id = $1 ORDER BY id LIMIT 1")
            .bind(tenant_id)
            .fetch_optional(&mut *tx)
            .await
            .ok()
            .flatten()
    };
    let _ = tx.commit().await;
    Ok((tenant_id, client_id))
}

pub async fn ingest_hit(
    app_pool: &PgPool,
    tenant_id: i64,
    client_id: Option<i64>,
    hit: &HoneyHit,
    decision: &HoneyDecision,
) -> Result<IngestResult, String> {
    let mut tx = crate::db::begin_tenant_tx(app_pool, tenant_id)
        .await
        .map_err(|e| e.to_string())?;

    let signals = json!(decision.scanner_signals).to_string();
    let mitre = json!(decision.mitre_techniques).to_string();
    let meta = decision_metadata(hit, decision).to_string();
    let session_id: i64 = sqlx::query_scalar(
        r#"INSERT INTO honey_route_sessions (
                tenant_id, client_id, session_fp, source_ip, user_agent, decoy_path,
                confidence, high_confidence, lateral_attempt, scanner_signals,
                mitre_techniques, hit_count, last_payload_at, metadata
           ) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10::jsonb,$11::jsonb,1,now(),$12::jsonb)
           ON CONFLICT (tenant_id, session_fp) DO UPDATE SET
                source_ip = EXCLUDED.source_ip,
                user_agent = EXCLUDED.user_agent,
                decoy_path = EXCLUDED.decoy_path,
                confidence = GREATEST(honey_route_sessions.confidence, EXCLUDED.confidence),
                high_confidence = honey_route_sessions.high_confidence OR EXCLUDED.high_confidence,
                lateral_attempt = honey_route_sessions.lateral_attempt OR EXCLUDED.lateral_attempt,
                scanner_signals = honey_route_sessions.scanner_signals || EXCLUDED.scanner_signals,
                mitre_techniques = honey_route_sessions.mitre_techniques || EXCLUDED.mitre_techniques,
                hit_count = honey_route_sessions.hit_count + 1,
                last_payload_at = now(),
                metadata = EXCLUDED.metadata,
                updated_at = now()
           RETURNING id"#,
    )
    .bind(tenant_id)
    .bind(client_id)
    .bind(&decision.session_fp)
    .bind(&hit.source_ip)
    .bind(&hit.user_agent)
    .bind(&hit.path)
    .bind(decision.confidence as i32)
    .bind(decision.high_confidence)
    .bind(decision.lateral_attempt)
    .bind(&signals)
    .bind(&mitre)
    .bind(&meta)
    .fetch_one(&mut *tx)
    .await
    .map_err(|e| e.to_string())?;

    let shell = extract_shell_command(hit);
    let body = truncate_body(&hit.body, 8192);
    let headers_s = hit.headers.to_string();
    sqlx::query(
        r#"INSERT INTO honey_route_payloads (
                tenant_id, client_id, session_id, http_method, path, query_string,
                body_excerpt, headers_json, mitre_techniques, shell_command, decoy_kind
           ) VALUES ($1,$2,$3,$4,$5,$6,$7,$8::jsonb,$9::jsonb,$10,$11)"#,
    )
    .bind(tenant_id)
    .bind(client_id)
    .bind(session_id)
    .bind(&hit.method)
    .bind(&hit.path)
    .bind(&hit.query)
    .bind(&body)
    .bind(&headers_s)
    .bind(&mitre)
    .bind(shell.as_deref())
    .bind(&decision.decoy_kind)
    .execute(&mut *tx)
    .await
    .map_err(|e| e.to_string())?;

    tx.commit().await.map_err(|e| e.to_string())?;

    let mut confidence = decision.confidence as i32;
    let mut high_confidence = decision.high_confidence;
    if confidence < CONF_ACTIVE as i32 {
        if let Ok(mut tx2) = crate::db::begin_tenant_tx(app_pool, tenant_id).await {
            let distinct: i64 = sqlx::query_scalar(
                r#"SELECT COUNT(DISTINCT path)::bigint FROM honey_route_payloads
                    WHERE session_id = $1 AND tenant_id = $2"#,
            )
            .bind(session_id)
            .bind(tenant_id)
            .fetch_one(&mut *tx2)
            .await
            .unwrap_or(1);
            let escalated = escalate_confidence(confidence as u8, distinct);
            if escalated as i32 != confidence {
                let _ = sqlx::query(
                    "UPDATE honey_route_sessions SET confidence = GREATEST(confidence, $2), high_confidence = high_confidence OR $3, updated_at = now() WHERE id = $1",
                )
                .bind(session_id)
                .bind(escalated as i32)
                .bind(escalated >= CONF_ACTIVE)
                .execute(&mut *tx2)
                .await;
                confidence = escalated as i32;
                high_confidence = escalated >= CONF_ACTIVE;
            }
            let _ = tx2.commit().await;
        }
    }

    Ok(IngestResult {
        session_id,
        tenant_id,
        client_id,
        confidence,
        high_confidence,
        lateral_attempt: decision.lateral_attempt,
    })
}

pub async fn merge_browser_profile(
    app_pool: &PgPool,
    tenant_id: i64,
    session_id: i64,
    profile: &Value,
) -> Result<(), String> {
    let mut tx = crate::db::begin_tenant_tx(app_pool, tenant_id)
        .await
        .map_err(|e| e.to_string())?;
    let profile_s = profile.to_string();
    sqlx::query(
        r#"UPDATE honey_route_sessions
              SET browser_profile = COALESCE(browser_profile, '{}'::jsonb) || $2::jsonb,
                  updated_at = now()
            WHERE id = $1 AND tenant_id = $3"#,
    )
    .bind(session_id)
    .bind(&profile_s)
    .bind(tenant_id)
    .execute(&mut *tx)
    .await
    .map_err(|e| e.to_string())?;
    tx.commit().await.map_err(|e| e.to_string())?;
    Ok(())
}

/// Inject attacker + decoy nodes and drop Dijkstra edge cost on the live path.
pub async fn inject_risk_graph(
    app_pool: &PgPool,
    tenant_id: i64,
    client_id: i64,
    hit: &HoneyHit,
    decision: &HoneyDecision,
) -> Result<(), String> {
    let stats = crate::honey_routing::load_live_kev_epss_stats(
        app_pool,
        tenant_id,
        client_id,
        &hit.source_ip,
    )
    .await;
    let sampled = crate::honey_routing::sample_honey_weight(
        decision.confidence,
        &stats,
        &decision.session_fp,
        &decision.decoy_kind,
    );

    let mut tx = crate::db::begin_tenant_tx(app_pool, tenant_id)
        .await
        .map_err(|e| e.to_string())?;

    let attacker_key = format!("honey-attacker:{}", decision.session_fp);
    let decoy_key = format!("honey-decoy:{}", decision.decoy_kind);
    let attacker_label = format!("Honey-route attacker {}", hit.source_ip);
    let decoy_label = format!("Honey decoy {}", decision.decoy_kind);

    let from_id = upsert_node(
        &mut tx,
        tenant_id,
        client_id,
        NODE_NETWORK,
        &attacker_label,
        &attacker_key,
        &hit.source_ip,
    )
    .await?;
    let to_id = upsert_node(
        &mut tx,
        tenant_id,
        client_id,
        NODE_ASSET,
        &decoy_label,
        &decoy_key,
        &decision.decoy_kind,
    )
    .await?;

    sqlx::query(
        r#"INSERT INTO risk_graph_edges (tenant_id, client_id, from_node_id, to_node_id, edge_type, metadata)
           VALUES ($1,$2,$3,$4,$5,$6)
           ON CONFLICT (tenant_id, client_id, from_node_id, to_node_id, edge_type) DO UPDATE SET
                metadata = EXCLUDED.metadata"#,
    )
    .bind(tenant_id)
    .bind(client_id)
    .bind(from_id)
    .bind(to_id)
    .bind(EDGE_LEADS_TO)
    .bind(
        json!({
            "honey_weight": sampled.honey_weight,
            "honey_edge_cost": sampled.honey_edge_cost,
            "cvss_equivalent": sampled.cvss_equivalent,
            "weight_source": sampled.source,
            "live_n": sampled.live_n,
            "source": ENGINE_ID,
            "mitre": decision.mitre_techniques,
            "confidence": decision.confidence,
        })
        .to_string(),
    )
    .execute(&mut *tx)
    .await
    .map_err(|e| e.to_string())?;

    tx.commit().await.map_err(|e| e.to_string())?;
    Ok(())
}

async fn upsert_node(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    tenant_id: i64,
    client_id: i64,
    node_type: &str,
    label: &str,
    graph_key: &str,
    external_id: &str,
) -> Result<i64, String> {
    sqlx::query_scalar(
        r#"INSERT INTO risk_graph_nodes (
                tenant_id, client_id, node_type, label, external_id, metadata, graph_key, risk_score, is_choke_point
           ) VALUES ($1,$2,$3,$4,NULLIF($5,''),'{}',$6,80,false)
           ON CONFLICT (tenant_id, client_id, graph_key) DO UPDATE SET
                label = EXCLUDED.label,
                node_type = EXCLUDED.node_type
           RETURNING id"#,
    )
    .bind(tenant_id)
    .bind(client_id)
    .bind(node_type)
    .bind(label)
    .bind(external_id)
    .bind(graph_key)
    .fetch_one(&mut **tx)
    .await
    .map_err(|e| e.to_string())
}

pub async fn apply_fair_aro_floor(
    app_pool: &PgPool,
    tenant_id: i64,
    client_id: i64,
    session_id: i64,
) -> Result<f64, String> {
    let floor = fair_aro_floor();
    let mut tx = crate::db::begin_tenant_tx(app_pool, tenant_id)
        .await
        .map_err(|e| e.to_string())?;
    sqlx::query(
        r#"INSERT INTO honey_route_fair_overrides
                (tenant_id, client_id, aro_floor, reason, session_id, expires_at)
           VALUES ($1,$2,$3,'honey_route_live_attack',$4, now() + interval '24 hours')
           ON CONFLICT (tenant_id, client_id) DO UPDATE SET
                aro_floor = GREATEST(honey_route_fair_overrides.aro_floor, EXCLUDED.aro_floor),
                session_id = EXCLUDED.session_id,
                expires_at = EXCLUDED.expires_at"#,
    )
    .bind(tenant_id)
    .bind(client_id)
    .bind(floor)
    .bind(session_id)
    .execute(&mut *tx)
    .await
    .map_err(|e| e.to_string())?;
    tx.commit().await.map_err(|e| e.to_string())?;
    Ok(floor)
}

pub async fn dispatch_soar(
    app_pool: &PgPool,
    tenant_id: i64,
    client_id: Option<i64>,
    hit: &HoneyHit,
    decision: &HoneyDecision,
    session_id: i64,
) {
    if decision.confidence < CONF_ACTIVE && !decision.high_confidence {
        return;
    }
    let event = crate::soar_playbook::PlaybookEvent {
        kind: "honey_route_high_confidence".into(),
        tenant_id,
        client_id,
        finding_id: None,
        cluster_id: None,
        title: format!(
            "Honey-route {} from {} ({})",
            decision.decoy_kind, hit.source_ip, decision.confidence
        ),
        severity: "critical".into(),
        source: ENGINE_ID.into(),
        target: hit.source_ip.clone(),
        status: "OPEN".into(),
        cvss: Some(9.0),
        epss: Some(1.0),
        kev: false,
        kev_known_ransomware: false,
        cve: None,
        signature_hash: Some(decision.session_fp.clone()),
        internet_exposed: true,
    };
    let _ = crate::soar_playbook::dispatch_event(app_pool, event, false).await;

    if decision.high_confidence || decision.confidence >= CONF_ACTIVE {
        if let Ok(mut tx) = crate::db::begin_tenant_tx(app_pool, tenant_id).await {
            let _ = sqlx::query(
                "UPDATE honey_route_sessions SET soar_paged_at = COALESCE(soar_paged_at, now()) WHERE id = $1",
            )
            .bind(session_id)
            .execute(&mut *tx)
            .await;
            let _ = tx.commit().await;
        }
    }
}

pub fn emit_telemetry(
    tx: &Sender<String>,
    tenant_id: i64,
    ingested: &IngestResult,
    hit: &HoneyHit,
) {
    let payload = json!({
        "event": "honey_route_hit",
        "tenant_id": tenant_id,
        "client_id": ingested.client_id,
        "session_id": ingested.session_id,
        "confidence": ingested.confidence,
        "high_confidence": ingested.high_confidence,
        "lateral_attempt": ingested.lateral_attempt,
        "source_ip": hit.source_ip,
        "path": hit.path,
        "engine": ENGINE_ID,
    });
    let _ = tx.send(crate::http::tenant_stream::stamp_value(tenant_id, payload));
}

pub async fn dashboard_snapshot(
    pool: &PgPool,
    tenant_id: i64,
    client_id: i64,
) -> Result<Value, String> {
    let mut tx = crate::db::begin_tenant_tx(pool, tenant_id)
        .await
        .map_err(|e| e.to_string())?;

    let sessions_24h: i64 = sqlx::query_scalar(
        r#"SELECT COUNT(*)::bigint FROM honey_route_sessions
            WHERE tenant_id = $1 AND client_id = $2 AND last_payload_at > now() - interval '24 hours'"#,
    )
    .bind(tenant_id)
    .bind(client_id)
    .fetch_one(&mut *tx)
    .await
    .unwrap_or(0);

    let high_conf: i64 = sqlx::query_scalar(
        r#"SELECT COUNT(*)::bigint FROM honey_route_sessions
            WHERE tenant_id = $1 AND client_id = $2 AND high_confidence
              AND last_payload_at > now() - interval '24 hours'"#,
    )
    .bind(tenant_id)
    .bind(client_id)
    .fetch_one(&mut *tx)
    .await
    .unwrap_or(0);

    let payloads_24h: i64 = sqlx::query_scalar(
        r#"SELECT COUNT(*)::bigint FROM honey_route_payloads
            WHERE tenant_id = $1 AND client_id = $2 AND created_at > now() - interval '24 hours'"#,
    )
    .bind(tenant_id)
    .bind(client_id)
    .fetch_one(&mut *tx)
    .await
    .unwrap_or(0);

    let lateral: i64 = sqlx::query_scalar(
        r#"SELECT COUNT(*)::bigint FROM honey_route_sessions
            WHERE tenant_id = $1 AND client_id = $2 AND lateral_attempt"#,
    )
    .bind(tenant_id)
    .bind(client_id)
    .fetch_one(&mut *tx)
    .await
    .unwrap_or(0);

    let aro: Option<f64> = sqlx::query_scalar(
        r#"SELECT aro_floor FROM honey_route_fair_overrides
            WHERE tenant_id = $1 AND client_id = $2
              AND (expires_at IS NULL OR expires_at > now())"#,
    )
    .bind(tenant_id)
    .bind(client_id)
    .fetch_optional(&mut *tx)
    .await
    .ok()
    .flatten();

    let recent = sqlx::query(
        r#"SELECT id, source_ip, user_agent, decoy_path, confidence, high_confidence,
                  lateral_attempt, hit_count, mitre_techniques, last_payload_at,
                  isolate_requested_by, isolate_approved_by, soar_isolated_at
             FROM honey_route_sessions
            WHERE tenant_id = $1 AND client_id = $2
            ORDER BY last_payload_at DESC
            LIMIT 40"#,
    )
    .bind(tenant_id)
    .bind(client_id)
    .fetch_all(&mut *tx)
    .await
    .unwrap_or_default();

    let sessions: Vec<Value> = recent
        .into_iter()
        .map(|r| {
            json!({
                "id": r.try_get::<i64,_>("id").unwrap_or(0),
                "source_ip": r.try_get::<String,_>("source_ip").unwrap_or_default(),
                "user_agent": r.try_get::<String,_>("user_agent").unwrap_or_default(),
                "decoy_path": r.try_get::<String,_>("decoy_path").unwrap_or_default(),
                "confidence": r.try_get::<i32,_>("confidence").unwrap_or(0),
                "high_confidence": r.try_get::<bool,_>("high_confidence").unwrap_or(false),
                "lateral_attempt": r.try_get::<bool,_>("lateral_attempt").unwrap_or(false),
                "hit_count": r.try_get::<i32,_>("hit_count").unwrap_or(0),
                "mitre_techniques": r.try_get::<Value,_>("mitre_techniques").unwrap_or(json!([])),
                "last_payload_at": r.try_get::<chrono::DateTime<chrono::Utc>,_>("last_payload_at")
                    .ok()
                    .map(|t| t.to_rfc3339()),
                "isolate_requested_by": r.try_get::<Option<i64>,_>("isolate_requested_by").ok().flatten(),
                "isolate_approved_by": r.try_get::<Option<i64>,_>("isolate_approved_by").ok().flatten(),
                "isolated": r.try_get::<Option<chrono::DateTime<chrono::Utc>>,_>("soar_isolated_at").ok().flatten().is_some(),
            })
        })
        .collect();

    let _ = tx.commit().await;
    Ok(json!({
        "engine": ENGINE_ID,
        "sessions_24h": sessions_24h,
        "payloads_24h": payloads_24h,
        "high_confidence_24h": high_conf,
        "lateral_attempts": lateral,
        "fair_aro_floor": aro,
        "fair_bleed": aro.map(|a| json!({
            "aro_floor": a,
            "note": "Live honey-route attack floors FAIR ARO; ALE recomputes on next financial snapshot."
        })),
        "sessions": sessions,
        "decoys": [
            crate::honey_routing::DECOY_ADMIN,
            crate::honey_routing::DECOY_SHELL,
        ],
        "soar_cooldown_seconds": SOAR_COOLDOWN_SECS,
        "confidence_policy": {
            "passive": crate::honey_routing::CONF_PASSIVE,
            "enumeration": crate::honey_routing::CONF_ENUMERATION,
            "active": CONF_ACTIVE,
            "soar_min": CONF_ACTIVE
        },
        "honey_weight_policy": {
            "source": "live_kev_epss_gaussian",
            "cvss_spectrum": "1.0-10.0",
            "typical": crate::honey_routing::honey_edge_weight(crate::honey_routing::CONF_PASSIVE),
            "note": "leads_to costs sampled from live CISA KEV + EPSS of client findings; never a 0.64–0.80 clamp"
        },
        "mimicry": {
            "ttfb": "gaussian_live_401",
            "bootstrap_mean_ms": 8.5,
            "bootstrap_std_ms": 2.1
        }
    }))
}

pub async fn session_payloads(
    pool: &PgPool,
    tenant_id: i64,
    client_id: i64,
    session_id: i64,
) -> Result<Vec<Value>, String> {
    let mut tx = crate::db::begin_tenant_tx(pool, tenant_id)
        .await
        .map_err(|e| e.to_string())?;
    let rows = sqlx::query(
        r#"SELECT id, http_method, path, query_string, body_excerpt, shell_command,
                  decoy_kind, mitre_techniques, created_at
             FROM honey_route_payloads
            WHERE tenant_id = $1 AND client_id = $2 AND session_id = $3
            ORDER BY created_at DESC
            LIMIT 200"#,
    )
    .bind(tenant_id)
    .bind(client_id)
    .bind(session_id)
    .fetch_all(&mut *tx)
    .await
    .map_err(|e| e.to_string())?;
    let _ = tx.commit().await;
    Ok(rows
        .into_iter()
        .map(|r| {
            json!({
                "id": r.try_get::<i64,_>("id").unwrap_or(0),
                "method": r.try_get::<String,_>("http_method").unwrap_or_default(),
                "path": r.try_get::<String,_>("path").unwrap_or_default(),
                "query": r.try_get::<String,_>("query_string").unwrap_or_default(),
                "body_excerpt": r.try_get::<String,_>("body_excerpt").unwrap_or_default(),
                "shell_command": r.try_get::<Option<String>,_>("shell_command").ok().flatten(),
                "decoy_kind": r.try_get::<String,_>("decoy_kind").unwrap_or_default(),
                "mitre_techniques": r.try_get::<Value,_>("mitre_techniques").unwrap_or(json!([])),
                "created_at": r.try_get::<chrono::DateTime<chrono::Utc>,_>("created_at")
                    .ok()
                    .map(|t| t.to_rfc3339()),
            })
        })
        .collect())
}

/// Post-ingest side effects: graph, FAIR, SOAR, telemetry. Never blocks the decoy response.
pub fn spawn_enrichment(
    pool: PgPool,
    telemetry: Sender<String>,
    hit: HoneyHit,
    decision: HoneyDecision,
    ingested: IngestResult,
) {
    tokio::spawn(async move {
        if let Some(cid) = ingested.client_id {
            let _ = inject_risk_graph(&pool, ingested.tenant_id, cid, &hit, &decision).await;
            let _ = apply_fair_aro_floor(&pool, ingested.tenant_id, cid, ingested.session_id).await;
            let _ = crate::financial_risk::compute_and_store(&pool, ingested.tenant_id, cid).await;
            let _ = crate::attack_path::compute_and_store(&pool, ingested.tenant_id, cid, Some(25))
                .await;
        }
        if ingested.confidence >= CONF_ACTIVE as i32 {
            let mut decision = decision;
            decision.confidence = ingested.confidence.clamp(0, 100) as u8;
            decision.high_confidence = ingested.high_confidence;
            dispatch_soar(
                &pool,
                ingested.tenant_id,
                ingested.client_id,
                &hit,
                &decision,
                ingested.session_id,
            )
            .await;
        }
        emit_telemetry(&telemetry, ingested.tenant_id, &ingested, &hit);
    });
}

pub async fn request_isolate(
    pool: &PgPool,
    tenant_id: i64,
    client_id: i64,
    session_id: i64,
    operator_id: i64,
) -> Result<Value, String> {
    let mut tx = crate::db::begin_tenant_tx(pool, tenant_id)
        .await
        .map_err(|e| e.to_string())?;
    let row = sqlx::query(
        r#"SELECT id, isolate_requested_by, soar_isolated_at
             FROM honey_route_sessions
            WHERE id = $1 AND tenant_id = $2 AND client_id = $3"#,
    )
    .bind(session_id)
    .bind(tenant_id)
    .bind(client_id)
    .fetch_optional(&mut *tx)
    .await
    .map_err(|e| e.to_string())?
    .ok_or_else(|| "session not found".to_string())?;
    if row
        .try_get::<Option<chrono::DateTime<chrono::Utc>>, _>("soar_isolated_at")
        .ok()
        .flatten()
        .is_some()
    {
        return Err("session already isolated".into());
    }
    sqlx::query(
        r#"UPDATE honey_route_sessions
              SET isolate_requested_by = $2, isolate_requested_at = now(), updated_at = now()
            WHERE id = $1"#,
    )
    .bind(session_id)
    .bind(operator_id)
    .execute(&mut *tx)
    .await
    .map_err(|e| e.to_string())?;
    tx.commit().await.map_err(|e| e.to_string())?;
    Ok(json!({
        "ok": true,
        "session_id": session_id,
        "isolate_requested_by": operator_id,
        "needs_second_admin": true
    }))
}

pub async fn approve_isolate(
    pool: &PgPool,
    tenant_id: i64,
    client_id: i64,
    session_id: i64,
    operator_id: i64,
    confirm: &str,
) -> Result<Value, String> {
    if confirm != "ISOLATE" {
        return Err("confirm must be ISOLATE".into());
    }
    let mut tx = crate::db::begin_tenant_tx(pool, tenant_id)
        .await
        .map_err(|e| e.to_string())?;
    let row = sqlx::query(
        r#"SELECT source_ip, isolate_requested_by, soar_isolated_at
             FROM honey_route_sessions
            WHERE id = $1 AND tenant_id = $2 AND client_id = $3"#,
    )
    .bind(session_id)
    .bind(tenant_id)
    .bind(client_id)
    .fetch_optional(&mut *tx)
    .await
    .map_err(|e| e.to_string())?
    .ok_or_else(|| "session not found".to_string())?;
    if row
        .try_get::<Option<chrono::DateTime<chrono::Utc>>, _>("soar_isolated_at")
        .ok()
        .flatten()
        .is_some()
    {
        return Err("session already isolated".into());
    }
    let requested_by = row
        .try_get::<Option<i64>, _>("isolate_requested_by")
        .ok()
        .flatten()
        .ok_or_else(|| "no isolate request pending — first admin must request".to_string())?;
    if requested_by == operator_id {
        return Err("second admin must be a different operator (dual-control)".into());
    }
    let source_ip: String = row.try_get("source_ip").unwrap_or_default();
    sqlx::query(
        r#"UPDATE honey_route_sessions
              SET isolate_approved_by = $2, isolate_approved_at = now(), updated_at = now()
            WHERE id = $1"#,
    )
    .bind(session_id)
    .bind(operator_id)
    .execute(&mut *tx)
    .await
    .map_err(|e| e.to_string())?;
    tx.commit().await.map_err(|e| e.to_string())?;

    let cmd = crate::soar::engine::build_command(
        "isolate_host",
        tenant_id,
        Some(client_id),
        None,
        source_ip.clone(),
        json!({"target": source_ip, "duration_seconds": 3600}),
        crate::soar::types::ThreatEvidence {
            finding_id: None,
            title: format!("HITL isolate honey-route session {session_id}"),
            severity: "critical".into(),
            source: ENGINE_ID.into(),
            target: source_ip.clone(),
            cve: None,
            signature_hash: Some(format!("honey-isolate:{session_id}")),
            cvss: Some(9.0),
            epss: Some(1.0),
            kev: false,
            internet_exposed: true,
            trigger_kind: "honey_route_isolate_hitl".into(),
        },
        false,
    );
    let outcome = crate::soar::engine::execute_armored_action(pool, cmd).await;
    if outcome.status == "ok" || outcome.status == "queued" {
        if let Ok(mut tx2) = crate::db::begin_tenant_tx(pool, tenant_id).await {
            let _ = sqlx::query(
                "UPDATE honey_route_sessions SET soar_isolated_at = now() WHERE id = $1",
            )
            .bind(session_id)
            .execute(&mut *tx2)
            .await;
            let _ = tx2.commit().await;
        }
    }
    Ok(json!({
        "ok": outcome.status == "ok" || outcome.status == "queued",
        "session_id": session_id,
        "requested_by": requested_by,
        "approved_by": operator_id,
        "soar": { "status": outcome.status, "detail": outcome.detail }
    }))
}
