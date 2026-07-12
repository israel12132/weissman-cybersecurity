/// `GET /api/metrics/dashboard` — tenant-scoped operational metrics for the metrics UI.
async fn api_metrics_dashboard(
    State(state): State<Arc<AppState>>,
    Extension(auth): Extension<AuthContext>,
) -> Response {
    let postgres_ok = sqlx::query_scalar::<_, i32>("SELECT 1")
        .fetch_one(state.app_pool.as_ref())
        .await
        .is_ok();

    let empty_sev = json!({
        "critical": 0,
        "high": 0,
        "medium": 0,
        "low": 0,
        "info": 0,
    });

    if !postgres_ok {
        return (
            StatusCode::OK,
            Json(json!({
                "postgres_ok": false,
                "active_scans": 0,
                "findings_by_severity": empty_sev,
                "jobs": { "completed_24h": 0, "failed_24h": 0 },
            })),
        )
            .into_response();
    }

    let Ok(mut tx) = db::begin_tenant_tx(&state.app_pool, auth.tenant_id).await else {
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(json!({
                "postgres_ok": false,
                "active_scans": 0,
                "findings_by_severity": empty_sev,
                "jobs": { "completed_24h": 0, "failed_24h": 0 },
            })),
        )
            .into_response();
    };

    let sev_rows: Vec<(String, i64)> = sqlx::query_as::<_, (String, i64)>(
        "SELECT COALESCE(lower(severity),'info') AS s, COUNT(*)::bigint
           FROM vulnerabilities
          WHERE COALESCE(status,'OPEN') NOT IN ('FIXED','FALSE_POSITIVE')
          GROUP BY s",
    )
    .fetch_all(&mut *tx)
    .await
    .unwrap_or_default();

    let sev_get = |rows: &[(String, i64)], k: &str| -> i64 {
        rows.iter()
            .find(|(s, _)| s == k)
            .map(|(_, n)| *n)
            .unwrap_or(0)
    };

    let active_scans: i64 = sqlx::query_scalar(
        "SELECT COUNT(*)::bigint FROM weissman_async_jobs
          WHERE tenant_id = $1 AND status = 'running'",
    )
    .bind(auth.tenant_id)
    .fetch_one(&mut *tx)
    .await
    .unwrap_or(0);

    let jobs_completed_24h: i64 = sqlx::query_scalar(
        "SELECT COUNT(*)::bigint FROM weissman_async_jobs
          WHERE tenant_id = $1 AND status = 'completed'
            AND updated_at > now() - interval '24 hours'",
    )
    .bind(auth.tenant_id)
    .fetch_one(&mut *tx)
    .await
    .unwrap_or(0);

    let jobs_failed_24h: i64 = sqlx::query_scalar(
        "SELECT COUNT(*)::bigint FROM weissman_async_jobs
          WHERE tenant_id = $1 AND status IN ('failed','dead')
            AND updated_at > now() - interval '24 hours'",
    )
    .bind(auth.tenant_id)
    .fetch_one(&mut *tx)
    .await
    .unwrap_or(0);

    let _ = tx.commit().await;

    let orchestrator_cycles = crate::orchestrator::active_tenant_scan_count() as i64;
    let active_scans = active_scans.max(orchestrator_cycles);

    (
        StatusCode::OK,
        Json(json!({
            "postgres_ok": true,
            "active_scans": active_scans,
            "findings_by_severity": {
                "critical": sev_get(&sev_rows, "critical"),
                "high":     sev_get(&sev_rows, "high"),
                "medium":   sev_get(&sev_rows, "medium"),
                "low":      sev_get(&sev_rows, "low"),
                "info":     sev_get(&sev_rows, "info"),
            },
            "jobs": {
                "completed_24h": jobs_completed_24h,
                "failed_24h":    jobs_failed_24h,
            },
        })),
    )
        .into_response()
}

async fn api_dashboard_stats(State(state): State<Arc<AppState>>, Extension(auth): Extension<AuthContext>) -> Response {
    let Ok(mut tx) = db::begin_tenant_tx(&state.app_pool, auth.tenant_id).await else {
        return (StatusCode::SERVICE_UNAVAILABLE, Json(json!({"total_vulnerabilities":0,"active_scans":0,"security_score":0,"assets_monitored":0,"threats_mitigated":0}))).into_response();
    };
    let vuln_count: i64 = sqlx::query_scalar::<_, i64>("SELECT COUNT(*)::bigint FROM vulnerabilities")
        .fetch_one(&mut *tx).await.unwrap_or(0);
    let client_count: i64 = sqlx::query_scalar::<_, i64>("SELECT COUNT(*)::bigint FROM clients")
        .fetch_one(&mut *tx).await.unwrap_or(0);
    let score: i64 = sqlx::query_scalar::<_, String>("SELECT summary FROM report_runs ORDER BY created_at DESC LIMIT 1")
        .fetch_optional(&mut *tx).await.ok().flatten()
        .and_then(|s| serde_json::from_str::<Value>(&s).ok())
        .and_then(|j| {
            let by = j.get("by_severity")?.as_object()?;
            let crit = by.get("critical").and_then(Value::as_i64).unwrap_or(0);
            let high = by.get("high").and_then(Value::as_i64).unwrap_or(0);
            let med = by.get("medium").and_then(Value::as_i64).unwrap_or(0);
            Some((100i64 - crit * 25 - high * 15 - med * 5).max(0))
        }).unwrap_or(0);
    let summary_json: Option<Value> = sqlx::query_scalar::<_, String>("SELECT summary FROM report_runs ORDER BY created_at DESC LIMIT 1")
        .fetch_optional(&mut *tx).await.ok().flatten()
        .and_then(|s| serde_json::from_str::<Value>(&s).ok());
    let _ = tx.commit().await;
    let active = crate::orchestrator::is_scanning_active();
    let attack_surface_targets = summary_json.as_ref().and_then(|j| j.get("attack_surface_targets")).and_then(Value::as_u64).unwrap_or(0) as i64;
    let attack_surface_paths = summary_json.as_ref().and_then(|j| j.get("attack_surface_paths")).and_then(Value::as_u64).unwrap_or(0) as i64;
    (StatusCode::OK, Json(json!({
        "total_vulnerabilities": vuln_count,
        "active_scans": if active { 1 } else { 0 },
        "security_score": score,
        "assets_monitored": client_count,
        "threats_mitigated": vuln_count,
        "attack_surface_targets": attack_surface_targets,
        "attack_surface_paths": attack_surface_paths,
    }))).into_response()
}

/// `GET /api/dashboard/exec-kpis` — Single aggregated payload for the executive dashboard.
///
/// Returns counts, trends, top-N rankings, MITRE coverage, severity-over-time sparkline
/// data, agent state, and job pipeline status in **one round-trip** so the cockpit hero
/// doesn't fire 7 parallel requests on every focus change. Wiz / Falcon / Snyk all
/// expose a similar endpoint — it's table stakes for a real-time dashboard.
///
/// Shape (stable contract; new fields are additive):
/// ```jsonc
/// {
///   "severity": { "critical": 12, "high": 47, "medium": 88, "low": 14, "info": 3 },
///   "severity_delta_24h": { "critical": +3, "high": -1, ... },
///   "open_vs_resolved": { "open": 160, "acknowledged": 8, "in_progress": 12,
///                        "fixed": 220, "false_positive": 18 },
///   "assets": { "total_clients": 7, "with_findings": 5 },
///   "agents": { "registered": 4, "online": 3, "stale": 1 },
///   "jobs": { "pending": 0, "running": 1, "failed_24h": 0, "completed_24h": 42 },
///   "scan_velocity": { "scans_24h": 42, "avg_scan_secs": 18.4 },
///   "mttr_hours": 6.8,
///   "security_score": 73,
///   "scoring": { "method": "weighted_severity", "weights": { ... } },
///   "trend": { // 24 hourly buckets, newest last
///     "labels": ["00:00","01:00", ...],
///     "discovered": [3, 1, 0, ...],
///     "resolved":   [0, 2, 4, ...]
///   },
///   "mitre_top": [ { "id": "T1190", "tactic": "initial_access", "hits": 12 }, ... ],
///   "engines_top": [ { "id": "asm", "hits": 88, "critical": 4 }, ... ],
///   "clients_top": [ { "id": 1, "name": "Acme", "open_critical": 3, "score": 62 }, ... ],
///   "cves_top":    [ { "cve": "CVE-2024-1234", "hits": 5, "severity": "critical" }, ... ],
///   "last_updated_unix": 1717340000
/// }
/// ```
async fn api_dashboard_exec_kpis(
    State(state): State<Arc<AppState>>,
    Extension(auth): Extension<AuthContext>,
) -> Response {
    let Ok(mut tx) = db::begin_tenant_tx(&state.app_pool, auth.tenant_id).await else {
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(json!({ "ok": false, "detail": "Database unavailable" })),
        )
            .into_response();
    };

    // ── Severity counts (current + 24h-ago snapshot for trend deltas) ──────────────
    let now_sev: Vec<(String, i64)> = sqlx::query_as::<_, (String, i64)>(
        "SELECT COALESCE(lower(severity),'info') AS s, COUNT(*)::bigint
           FROM vulnerabilities
          WHERE COALESCE(status,'OPEN') NOT IN ('FIXED','FALSE_POSITIVE')
          GROUP BY s",
    )
    .fetch_all(&mut *tx)
    .await
    .unwrap_or_default();

    let prev_sev: Vec<(String, i64)> = sqlx::query_as::<_, (String, i64)>(
        "SELECT COALESCE(lower(severity),'info') AS s, COUNT(*)::bigint
           FROM vulnerabilities
          WHERE discovered_at < now() - interval '24 hours'
            AND COALESCE(status,'OPEN') NOT IN ('FIXED','FALSE_POSITIVE')
          GROUP BY s",
    )
    .fetch_all(&mut *tx)
    .await
    .unwrap_or_default();

    let to_map = |rows: Vec<(String, i64)>| {
        let mut m: std::collections::HashMap<String, i64> = std::collections::HashMap::new();
        for (k, v) in rows {
            m.insert(k, v);
        }
        m
    };
    let sev_now = to_map(now_sev);
    let sev_prev = to_map(prev_sev);
    let sev_get = |m: &std::collections::HashMap<String, i64>, k: &str| -> i64 {
        m.get(k).copied().unwrap_or(0)
    };

    // ── Status workflow breakdown ──────────────────────────────────────────────────
    let status_rows: Vec<(String, i64)> = sqlx::query_as::<_, (String, i64)>(
        "SELECT COALESCE(upper(status),'OPEN'), COUNT(*)::bigint
           FROM vulnerabilities GROUP BY 1",
    )
    .fetch_all(&mut *tx)
    .await
    .unwrap_or_default();
    let status_map = to_map(status_rows);

    // ── Asset / client counts ──────────────────────────────────────────────────────
    let total_clients: i64 =
        sqlx::query_scalar("SELECT COUNT(*)::bigint FROM clients")
            .fetch_one(&mut *tx)
            .await
            .unwrap_or(0);
    let clients_with_findings: i64 = sqlx::query_scalar(
        "SELECT COUNT(DISTINCT client_id)::bigint FROM vulnerabilities
          WHERE COALESCE(status,'OPEN') NOT IN ('FIXED','FALSE_POSITIVE')",
    )
    .fetch_one(&mut *tx)
    .await
    .unwrap_or(0);

    // ── Endpoint agent state (registered / online / stale) ─────────────────────────
    // Tolerate the endpoint_agents table being absent on very old schemas.
    let agents_registered: i64 = sqlx::query_scalar(
        "SELECT COUNT(*)::bigint FROM endpoint_agents WHERE tenant_id = $1",
    )
    .bind(auth.tenant_id)
    .fetch_one(&mut *tx)
    .await
    .unwrap_or(0);
    let agents_online: i64 = sqlx::query_scalar(
        "SELECT COUNT(*)::bigint FROM endpoint_agents
          WHERE tenant_id = $1 AND last_seen_at > now() - interval '90 seconds'",
    )
    .bind(auth.tenant_id)
    .fetch_one(&mut *tx)
    .await
    .unwrap_or(0);

    // ── Job pipeline (pending / running / 24h completed / 24h failed) ──────────────
    // weissman_async_jobs is intentionally RLS-free (cross-tenant worker dequeue), so begin_tenant_tx
    // does NOT scope it — every query below must carry an explicit `tenant_id = $1` filter or it would
    // aggregate every tenant's jobs (mirrors the correct api_metrics_dashboard sibling above).
    let jobs_pending: i64 = sqlx::query_scalar(
        "SELECT COUNT(*)::bigint FROM weissman_async_jobs WHERE status = 'pending' AND tenant_id = $1",
    )
    .bind(auth.tenant_id)
    .fetch_one(&mut *tx)
    .await
    .unwrap_or(0);
    let jobs_running: i64 = sqlx::query_scalar(
        "SELECT COUNT(*)::bigint FROM weissman_async_jobs WHERE status = 'running' AND tenant_id = $1",
    )
    .bind(auth.tenant_id)
    .fetch_one(&mut *tx)
    .await
    .unwrap_or(0);
    let jobs_completed_24h: i64 = sqlx::query_scalar(
        "SELECT COUNT(*)::bigint FROM weissman_async_jobs
          WHERE status = 'completed' AND updated_at > now() - interval '24 hours' AND tenant_id = $1",
    )
    .bind(auth.tenant_id)
    .fetch_one(&mut *tx)
    .await
    .unwrap_or(0);
    let jobs_failed_24h: i64 = sqlx::query_scalar(
        "SELECT COUNT(*)::bigint FROM weissman_async_jobs
          WHERE status IN ('failed','dead') AND updated_at > now() - interval '24 hours' AND tenant_id = $1",
    )
    .bind(auth.tenant_id)
    .fetch_one(&mut *tx)
    .await
    .unwrap_or(0);

    // ── Average scan duration over the last 24h ────────────────────────────────────
    let avg_scan_secs: f64 = sqlx::query_scalar::<_, Option<f64>>(
        "SELECT AVG(EXTRACT(EPOCH FROM (updated_at - created_at)))::float8
           FROM weissman_async_jobs
          WHERE status = 'completed' AND updated_at > now() - interval '24 hours' AND tenant_id = $1",
    )
    .bind(auth.tenant_id)
    .fetch_one(&mut *tx)
    .await
    .ok()
    .flatten()
    .unwrap_or(0.0);

    // ── MTTR (open → fixed, last 30 days) ──────────────────────────────────────────
    let mttr_hours: f64 = sqlx::query_scalar::<_, Option<f64>>(
        "SELECT AVG(EXTRACT(EPOCH FROM (updated_at - discovered_at)) / 3600.0)::float8
           FROM vulnerabilities
          WHERE upper(status) = 'FIXED'
            AND updated_at > now() - interval '30 days'",
    )
    .fetch_one(&mut *tx)
    .await
    .ok()
    .flatten()
    .unwrap_or(0.0);

    // ── 24-hour bucket trend (discovered vs resolved) ──────────────────────────────
    let trend_disc: Vec<(i32, i64)> = sqlx::query_as::<_, (i32, i64)>(
        "SELECT EXTRACT(HOUR FROM discovered_at)::int AS h, COUNT(*)::bigint
           FROM vulnerabilities
          WHERE discovered_at > now() - interval '24 hours'
          GROUP BY h",
    )
    .fetch_all(&mut *tx)
    .await
    .unwrap_or_default();
    let trend_res: Vec<(i32, i64)> = sqlx::query_as::<_, (i32, i64)>(
        "SELECT EXTRACT(HOUR FROM updated_at)::int AS h, COUNT(*)::bigint
           FROM vulnerabilities
          WHERE upper(status) IN ('FIXED','FALSE_POSITIVE')
            AND updated_at > now() - interval '24 hours'
          GROUP BY h",
    )
    .fetch_all(&mut *tx)
    .await
    .unwrap_or_default();
    let bucket_disc = to_map_i(trend_disc);
    let bucket_res = to_map_i(trend_res);
    let now_hour = chrono::Timelike::hour(&chrono::Utc::now()) as i32;
    let mut labels = Vec::with_capacity(24);
    let mut series_disc = Vec::with_capacity(24);
    let mut series_res = Vec::with_capacity(24);
    for i in 0..24 {
        let h = (now_hour + 1 + i) % 24;
        labels.push(format!("{:02}:00", h));
        series_disc.push(bucket_disc.get(&h).copied().unwrap_or(0));
        series_res.push(bucket_res.get(&h).copied().unwrap_or(0));
    }

    // ── Top-N rankings ─────────────────────────────────────────────────────────────
    let engines_top: Vec<(String, i64, i64)> = sqlx::query_as::<_, (String, i64, i64)>(
        "SELECT source AS engine,
                COUNT(*)::bigint                              AS hits,
                COUNT(*) FILTER (WHERE lower(severity)='critical')::bigint AS crit
           FROM vulnerabilities
          WHERE COALESCE(status,'OPEN') NOT IN ('FIXED','FALSE_POSITIVE')
          GROUP BY source
          ORDER BY hits DESC
          LIMIT 8",
    )
    .fetch_all(&mut *tx)
    .await
    .unwrap_or_default();

    let clients_top: Vec<(i64, String, i64, i64)> =
        sqlx::query_as::<_, (i64, String, i64, i64)>(
            "SELECT c.id, c.name,
                    COUNT(v.id) FILTER (WHERE lower(v.severity)='critical')::bigint AS open_crit,
                    COUNT(v.id)::bigint AS total_open
               FROM clients c
               LEFT JOIN vulnerabilities v
                 ON v.client_id = c.id
                AND COALESCE(v.status,'OPEN') NOT IN ('FIXED','FALSE_POSITIVE')
              GROUP BY c.id, c.name
              ORDER BY open_crit DESC, total_open DESC
              LIMIT 8",
        )
        .fetch_all(&mut *tx)
        .await
        .unwrap_or_default();

    // CVE roll-up — pull from raw_data.cve / raw_data.raw.cve.
    let cve_rows: Vec<(String, String, i64)> = sqlx::query_as::<_, (String, String, i64)>(
        "SELECT COALESCE(NULLIF(raw_data->>'cve',''),
                          NULLIF(raw_data->'raw'->>'cve','')) AS cve,
                MIN(severity)        AS severity,
                COUNT(*)::bigint     AS hits
           FROM vulnerabilities
          WHERE (raw_data->>'cve' IS NOT NULL OR raw_data->'raw'->>'cve' IS NOT NULL)
            AND COALESCE(status,'OPEN') NOT IN ('FIXED','FALSE_POSITIVE')
          GROUP BY 1
          HAVING COALESCE(NULLIF(raw_data->>'cve',''),
                          NULLIF(raw_data->'raw'->>'cve','')) IS NOT NULL
          ORDER BY hits DESC
          LIMIT 8",
    )
    .fetch_all(&mut *tx)
    .await
    .unwrap_or_default();

    // MITRE roll-up — `raw_data.mitre_attack` is the ATT&CK technique id (e.g. T1190).
    let mitre_rows: Vec<(String, i64)> = sqlx::query_as::<_, (String, i64)>(
        "SELECT raw_data->>'mitre_attack' AS technique, COUNT(*)::bigint
           FROM vulnerabilities
          WHERE COALESCE(raw_data->>'mitre_attack','') <> ''
            AND COALESCE(status,'OPEN') NOT IN ('FIXED','FALSE_POSITIVE')
          GROUP BY technique
          ORDER BY count DESC
          LIMIT 12",
    )
    .fetch_all(&mut *tx)
    .await
    .unwrap_or_default();
    let _ = tx.commit().await;

    // ── Security score (weighted, clamped 0..100) ──────────────────────────────────
    let score = {
        let crit = sev_get(&sev_now, "critical");
        let high = sev_get(&sev_now, "high");
        let med = sev_get(&sev_now, "medium");
        let raw = 100i64 - crit * 25 - high * 10 - med * 3;
        raw.max(0).min(100)
    };

    // ── Helpers for the response payload ──────────────────────────────────────────
    let sev_obj = json!({
        "critical": sev_get(&sev_now, "critical"),
        "high":     sev_get(&sev_now, "high"),
        "medium":   sev_get(&sev_now, "medium"),
        "low":      sev_get(&sev_now, "low"),
        "info":     sev_get(&sev_now, "info"),
    });
    let sev_delta = json!({
        "critical": sev_get(&sev_now, "critical") - sev_get(&sev_prev, "critical"),
        "high":     sev_get(&sev_now, "high")     - sev_get(&sev_prev, "high"),
        "medium":   sev_get(&sev_now, "medium")   - sev_get(&sev_prev, "medium"),
        "low":      sev_get(&sev_now, "low")      - sev_get(&sev_prev, "low"),
        "info":     sev_get(&sev_now, "info")     - sev_get(&sev_prev, "info"),
    });
    let status_obj = json!({
        "open":           status_map.get("OPEN").copied().unwrap_or(0),
        "acknowledged":   status_map.get("ACKNOWLEDGED").copied().unwrap_or(0),
        "in_progress":    status_map.get("IN_PROGRESS").copied().unwrap_or(0),
        "fixed":          status_map.get("FIXED").copied().unwrap_or(0),
        "false_positive": status_map.get("FALSE_POSITIVE").copied().unwrap_or(0),
    });
    let mitre_top: Vec<Value> = mitre_rows
        .into_iter()
        .map(|(t, h)| json!({ "id": t.clone(), "tactic": mitre_tactic_for(&t), "hits": h }))
        .collect();
    let engines_top: Vec<Value> = engines_top
        .into_iter()
        .map(|(e, hits, crit)| json!({ "id": e, "hits": hits, "critical": crit }))
        .collect();
    let clients_top: Vec<Value> = clients_top
        .into_iter()
        .map(|(id, name, oc, total)| {
            json!({ "id": id, "name": name, "open_critical": oc, "total_open": total })
        })
        .collect();
    let cves_top: Vec<Value> = cve_rows
        .into_iter()
        .map(|(cve, sev, hits)| json!({ "cve": cve, "severity": sev, "hits": hits }))
        .collect();

    (
        StatusCode::OK,
        Json(json!({
            "ok": true,
            "severity": sev_obj,
            "severity_delta_24h": sev_delta,
            "open_vs_resolved": status_obj,
            "assets": {
                "total_clients": total_clients,
                "with_findings": clients_with_findings,
            },
            "agents": {
                "registered": agents_registered,
                "online":     agents_online,
                "stale":      (agents_registered - agents_online).max(0),
            },
            "jobs": {
                "pending":       jobs_pending,
                "running":       jobs_running,
                "completed_24h": jobs_completed_24h,
                "failed_24h":    jobs_failed_24h,
            },
            "scan_velocity": {
                "scans_24h":     jobs_completed_24h,
                "avg_scan_secs": (avg_scan_secs * 10.0).round() / 10.0,
            },
            "mttr_hours":     (mttr_hours * 10.0).round() / 10.0,
            "security_score": score,
            "scoring": {
                "method":  "weighted_severity",
                "weights": { "critical": 25, "high": 10, "medium": 3 },
                "max":     100
            },
            "trend": {
                "labels":     labels,
                "discovered": series_disc,
                "resolved":   series_res,
            },
            "mitre_top":   mitre_top,
            "engines_top": engines_top,
            "clients_top": clients_top,
            "cves_top":    cves_top,
            "last_updated_unix": Utc::now().timestamp(),
        })),
    )
        .into_response()
}

fn to_map_i(rows: Vec<(i32, i64)>) -> std::collections::HashMap<i32, i64> {
    let mut m = std::collections::HashMap::new();
    for (k, v) in rows {
        m.insert(k, v);
    }
    m
}

/// Best-effort tactic mapping for an ATT&CK technique ID. Not exhaustive — covers the
/// techniques our engines emit most often. Returns `"unknown"` for anything else.
fn mitre_tactic_for(technique: &str) -> &'static str {
    let t = technique.trim().to_ascii_uppercase();
    let prefix = t.split('.').next().unwrap_or("");
    match prefix {
        // Reconnaissance
        "T1589" | "T1590" | "T1591" | "T1592" | "T1593" | "T1594" | "T1595" | "T1596" | "T1597"
        | "T1598" => "reconnaissance",
        // Resource Development
        "T1583" | "T1584" | "T1585" | "T1586" | "T1587" | "T1588" => "resource_development",
        // Initial Access
        "T1078" | "T1133" | "T1189" | "T1190" | "T1199" | "T1200" | "T1566" => "initial_access",
        // Execution
        "T1059" | "T1106" | "T1127" | "T1129" | "T1203" | "T1204" => "execution",
        // Persistence
        "T1098" | "T1136" | "T1137" | "T1547" | "T1574" => "persistence",
        // Privilege Escalation
        "T1068" | "T1484" | "T1548" | "T1556" => "privilege_escalation",
        // Defense Evasion
        "T1027" | "T1036" | "T1070" | "T1140" | "T1218" | "T1222" | "T1497" | "T1562" | "T1564"
        | "T1620" => "defense_evasion",
        // Credential Access
        "T1003" | "T1110" | "T1187" | "T1212" | "T1552" | "T1555" | "T1557" | "T1606" | "T1649" => {
            "credential_access"
        }
        // Discovery
        "T1007" | "T1018" | "T1046" | "T1057" | "T1069" | "T1082" | "T1083" | "T1087" | "T1135"
        | "T1518" => "discovery",
        // Lateral Movement
        "T1021" | "T1080" | "T1210" | "T1534" | "T1550" => "lateral_movement",
        // Collection
        "T1005" | "T1056" | "T1074" | "T1113" | "T1115" | "T1530" | "T1560" => "collection",
        // Command & Control
        "T1071" | "T1090" | "T1095" | "T1102" | "T1104" | "T1219" | "T1572" | "T1571" => {
            "command_and_control"
        }
        // Exfiltration
        "T1011" | "T1020" | "T1029" | "T1041" | "T1048" | "T1052" | "T1567" => "exfiltration",
        // Impact
        "T1485" | "T1486" | "T1489" | "T1490" | "T1491" | "T1495" | "T1498" | "T1499" | "T1561"
        | "T1565" => "impact",
        _ => "unknown",
    }
}

/// `GET /api/findings/clusters` — collapsed view: one row per finding-cluster,
/// sorted by KEV/EPSS/severity. This is what the inbox should show by default;
/// the per-vulnerability list is for drill-down only.
async fn api_findings_clusters(
    State(state): State<Arc<AppState>>,
    Extension(auth): Extension<AuthContext>,
    Query(q): Query<std::collections::HashMap<String, String>>,
) -> Response {
    let limit: i64 = q.get("limit").and_then(|s| s.parse::<i64>().ok()).unwrap_or(100).clamp(1, 1000);
    let offset: i64 = q.get("offset").and_then(|s| s.parse::<i64>().ok()).unwrap_or(0).max(0);
    let severity = q.get("severity").map(|s| s.trim().to_lowercase()).filter(|s| !s.is_empty());
    let only_open = q.get("status").map(|s| s.trim().to_uppercase() == "OPEN").unwrap_or(false);
    let only_kev = q.get("kev").map(|s| s == "1" || s == "true").unwrap_or(false);
    let client_filter: Option<i64> = q.get("client_id").and_then(|s| s.parse().ok());

    let Ok(mut tx) = db::begin_tenant_tx(&state.app_pool, auth.tenant_id).await else {
        return (StatusCode::SERVICE_UNAVAILABLE, Json(json!({"ok": false, "detail": "DB unavailable"}))).into_response();
    };

    let rows = sqlx::query(
        r#"SELECT id, client_id, target, cwe, vuln_signature, title,
                  member_count, engines, sources, cves,
                  max_severity, max_cvss, max_epss, kev_listed,
                  status, first_seen_at, last_seen_at
             FROM weissman_finding_clusters
            WHERE ($3::text  IS NULL OR lower(max_severity) = $3)
              AND ($4::bool  IS NULL OR ($4 AND status = 'OPEN') OR NOT $4)
              AND ($5::bool  IS NULL OR ($5 AND kev_listed) OR NOT $5)
              AND ($6::bigint IS NULL OR client_id = $6)
            ORDER BY
                CASE WHEN kev_listed THEN 0 ELSE 1 END,
                COALESCE(max_epss, 0)::float DESC,
                CASE max_severity
                    WHEN 'critical' THEN 5 WHEN 'high' THEN 4
                    WHEN 'medium' THEN 3 WHEN 'low' THEN 2 ELSE 1 END DESC,
                last_seen_at DESC
            LIMIT $1 OFFSET $2"#,
    )
    .bind(limit)
    .bind(offset)
    .bind(severity.as_deref())
    .bind(only_open)
    .bind(only_kev)
    .bind(client_filter)
    .fetch_all(&mut *tx).await.unwrap_or_default();

    let total: i64 = sqlx::query_scalar(
        r#"SELECT COUNT(*)::bigint FROM weissman_finding_clusters
            WHERE ($1::text IS NULL OR lower(max_severity) = $1)
              AND ($2::bool IS NULL OR ($2 AND status = 'OPEN') OR NOT $2)
              AND ($3::bool IS NULL OR ($3 AND kev_listed) OR NOT $3)
              AND ($4::bigint IS NULL OR client_id = $4)"#,
    )
    .bind(severity.as_deref())
    .bind(only_open)
    .bind(only_kev)
    .bind(client_filter)
    .fetch_one(&mut *tx).await.unwrap_or(0);
    let _ = tx.commit().await;

    let clusters: Vec<Value> = rows.into_iter().map(|r| {
        let max_severity: String = r.try_get("max_severity").unwrap_or_else(|_| "info".to_string());
        let max_cvss: Option<f32> = r.try_get("max_cvss").ok();
        let max_epss: Option<f32> = r.try_get("max_epss").ok();
        let engines: Vec<String> = r.try_get("engines").unwrap_or_default();
        let sources: Vec<String> = r.try_get("sources").unwrap_or_default();
        let cves: Vec<String> = r.try_get("cves").unwrap_or_default();
        json!({
            "id":             r.try_get::<i64, _>("id").unwrap_or(0),
            "client_id":      r.try_get::<i64, _>("client_id").unwrap_or(0),
            "target":         r.try_get::<String, _>("target").unwrap_or_default(),
            "cwe":            r.try_get::<String, _>("cwe").unwrap_or_default(),
            "vuln_signature": r.try_get::<String, _>("vuln_signature").unwrap_or_default(),
            "title":          r.try_get::<String, _>("title").unwrap_or_default(),
            "member_count":   r.try_get::<i32, _>("member_count").unwrap_or(0),
            "engines":        engines,
            "sources":        sources,
            "cves":           cves,
            "max_severity":   max_severity,
            "max_cvss":       max_cvss,
            "max_epss":       max_epss,
            "kev_listed":     r.try_get::<bool, _>("kev_listed").unwrap_or(false),
            "status":         r.try_get::<String, _>("status").unwrap_or_default(),
            "first_seen_at":  r.try_get::<chrono::DateTime<Utc>, _>("first_seen_at").ok().map(|d| d.to_rfc3339()),
            "last_seen_at":   r.try_get::<chrono::DateTime<Utc>, _>("last_seen_at").ok().map(|d| d.to_rfc3339()),
        })
    }).collect();

    (StatusCode::OK, Json(json!({
        "ok": true,
        "clusters": clusters,
        "total": total,
        "limit": limit,
        "offset": offset,
    }))).into_response()
}

/// `GET /api/intel/suppressions` — list the tenant's active auto-suppressions.
async fn api_intel_suppressions(
    State(state): State<Arc<AppState>>,
    Extension(auth): Extension<AuthContext>,
) -> Response {
    let Ok(mut tx) = db::begin_tenant_tx(&state.app_pool, auth.tenant_id).await else {
        return (StatusCode::SERVICE_UNAVAILABLE, Json(json!({"ok": false}))).into_response();
    };
    let rows = sqlx::query(
        r#"SELECT id, engine, signature_hash, target_glob, reason,
                  fp_count_at_create, created_by_user_id, created_at,
                  expires_at, hit_count, last_hit_at
             FROM finding_suppressions
            ORDER BY created_at DESC LIMIT 200"#,
    )
    .fetch_all(&mut *tx).await.unwrap_or_default();
    let _ = tx.commit().await;
    let list: Vec<Value> = rows.into_iter().map(|r| json!({
        "id":             r.try_get::<i64, _>("id").unwrap_or(0),
        "engine":         r.try_get::<String, _>("engine").unwrap_or_default(),
        "signature_hash": r.try_get::<String, _>("signature_hash").unwrap_or_default(),
        "target_glob":    r.try_get::<Option<String>, _>("target_glob").ok().flatten(),
        "reason":         r.try_get::<String, _>("reason").unwrap_or_default(),
        "fp_count_at_create": r.try_get::<i32, _>("fp_count_at_create").unwrap_or(0),
        "created_by_user_id": r.try_get::<Option<i64>, _>("created_by_user_id").ok().flatten(),
        "created_at":     r.try_get::<chrono::DateTime<Utc>, _>("created_at").ok().map(|d| d.to_rfc3339()),
        "expires_at":     r.try_get::<Option<chrono::DateTime<Utc>>, _>("expires_at").ok().flatten().map(|d| d.to_rfc3339()),
        "hit_count":      r.try_get::<i32, _>("hit_count").unwrap_or(0),
        "last_hit_at":    r.try_get::<Option<chrono::DateTime<Utc>>, _>("last_hit_at").ok().flatten().map(|d| d.to_rfc3339()),
    })).collect();
    (StatusCode::OK, Json(json!({"ok": true, "suppressions": list}))).into_response()
}

/// `DELETE /api/intel/suppressions/:id` — undo a suppression (analyst override).
async fn api_intel_suppression_delete(
    State(state): State<Arc<AppState>>,
    Extension(auth): Extension<AuthContext>,
    Path(id): Path<i64>,
) -> Response {
    let Ok(mut tx) = db::begin_tenant_tx(&state.app_pool, auth.tenant_id).await else {
        return (StatusCode::SERVICE_UNAVAILABLE, Json(json!({"ok": false}))).into_response();
    };
    let res = sqlx::query("DELETE FROM finding_suppressions WHERE id = $1 AND tenant_id = $2")
        .bind(id).bind(auth.tenant_id)
        .execute(&mut *tx).await;
    let _ = tx.commit().await;
    match res {
        Ok(r) if r.rows_affected() > 0 => {
            (StatusCode::OK, Json(json!({"ok": true, "deleted": id}))).into_response()
        }
        Ok(_) => (StatusCode::NOT_FOUND, Json(json!({"ok": false}))).into_response(),
        Err(_) => (StatusCode::INTERNAL_SERVER_ERROR, Json(json!({"ok": false}))).into_response(),
    }
}

/// `GET /api/intel/status` — health view of the intel mirrors. Always public to the
/// authed UI so the cockpit can show "Last KEV refresh: 4 minutes ago".
async fn api_intel_status(State(state): State<Arc<AppState>>) -> Response {
    let kev_total: Option<i64> = sqlx::query_scalar("SELECT COUNT(*)::bigint FROM kev_intel")
        .fetch_optional(state.app_pool.as_ref()).await.ok().flatten();
    let kev_last: Option<chrono::DateTime<Utc>> = sqlx::query_scalar(
        "SELECT MAX(refreshed_at) FROM kev_intel",
    ).fetch_optional(state.app_pool.as_ref()).await.ok().flatten();
    let epss_total: Option<i64> = sqlx::query_scalar("SELECT COUNT(*)::bigint FROM epss_intel")
        .fetch_optional(state.app_pool.as_ref()).await.ok().flatten();
    let epss_last: Option<chrono::DateTime<Utc>> = sqlx::query_scalar(
        "SELECT MAX(refreshed_at) FROM epss_intel",
    ).fetch_optional(state.app_pool.as_ref()).await.ok().flatten();
    (StatusCode::OK, Json(json!({
        "ok": true,
        "kev":  { "rows": kev_total.unwrap_or(0),  "last_refresh": kev_last.map(|d| d.to_rfc3339())  },
        "epss": { "rows": epss_total.unwrap_or(0), "last_refresh": epss_last.map(|d| d.to_rfc3339()) },
    }))).into_response()
}

async fn api_findings(
    State(state): State<Arc<AppState>>,
    Extension(auth): Extension<AuthContext>,
    Query(q): Query<std::collections::HashMap<String, String>>,
) -> Response {
    // Server-side pagination + severity filter so the table doesn't ship 500 rows for a
    // 5-row request, and so clients can pull more than the default cap when needed.
    let limit: i64 = q
        .get("limit")
        .and_then(|s| s.parse::<i64>().ok())
        .unwrap_or(500)
        .clamp(1, 5000);
    let offset: i64 = q
        .get("offset")
        .and_then(|s| s.parse::<i64>().ok())
        .unwrap_or(0)
        .max(0);
    let severity_list: Vec<String> = q
        .get("severity")
        .map(|s| {
            s.split(',')
                .map(|x| x.trim().to_ascii_lowercase())
                .filter(|x| {
                    matches!(
                        x.as_str(),
                        "critical" | "high" | "medium" | "low" | "info"
                    )
                })
                .collect()
        })
        .unwrap_or_default();
    let severity_filter: Option<Vec<String>> = if severity_list.is_empty() {
        None
    } else {
        Some(severity_list)
    };
    let client_filter: Option<i64> = q
        .get("client_id")
        .and_then(|s| s.parse::<i64>().ok());

    let Ok(mut tx) = db::begin_tenant_tx(&state.app_pool, auth.tenant_id).await else {
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(json!({"ok": false, "detail": "Database unavailable", "findings": []})),
        )
            .into_response();
    };

    // Build SQL with deterministic bind ordering: $1 = limit, $2 = offset, $3 = severity (or
    // NULL placeholder), $4 = client_id (or NULL placeholder). Postgres ignores params we don't
    // reference, but using identical positions for the count query keeps things simple.
    let rows = sqlx::query(
        "SELECT id, finding_id, title, severity, source, status, client_id::text AS client_id, \
         COALESCE(description,'') AS description, discovered_at, \
         COALESCE(poc_sealed, false) AS poc_sealed, \
         COALESCE(poc_commitment_sha256,'') AS poc_commitment_sha256, \
         COALESCE(raw_data, '{}'::jsonb) AS raw_data, \
         epss_score, epss_percentile, kev_listed, kev_known_ransomware, kev_due_date, \
         intel_enriched_at, signature_hash, cluster_id, seen_count, \
         confidence_multiplier, effective_risk \
         FROM vulnerabilities \
         WHERE ($3::text[] IS NULL OR lower(severity) = ANY($3)) \
           AND ($4::bigint IS NULL OR client_id = $4) \
         ORDER BY \
            CASE WHEN kev_listed THEN 0 ELSE 1 END, \
            COALESCE(epss_score, 0) DESC, \
            discovered_at DESC \
         LIMIT $1 OFFSET $2",
    )
    .bind(limit)
    .bind(offset)
    .bind(severity_filter.as_ref().map(|v| v.as_slice()))
    .bind(client_filter)
    .fetch_all(&mut *tx)
    .await
    .unwrap_or_default();

    let total: i64 = sqlx::query_scalar::<_, i64>(
        "SELECT COUNT(*)::bigint FROM vulnerabilities \
         WHERE ($1::text[] IS NULL OR lower(severity) = ANY($1)) \
           AND ($2::bigint IS NULL OR client_id = $2)",
    )
    .bind(severity_filter.as_ref().map(|v| v.as_slice()))
    .bind(client_filter)
    .fetch_one(&mut *tx)
    .await
    .unwrap_or(0);
    let _ = tx.commit().await;

    // Batch-load FP/TP confidence multipliers in ONE query (fixes the N+1 where
    // every row opened its own tenant transaction + query).
    let conf_pairs: Vec<(String, String)> = rows
        .iter()
        .filter_map(|r| {
            let eng = r.try_get::<String, _>("source").ok()?;
            let sig = r
                .try_get::<Option<String>, _>("signature_hash")
                .ok()
                .flatten()?;
            if eng.is_empty() || sig.is_empty() {
                None
            } else {
                Some((eng, sig))
            }
        })
        .collect();
    let conf_map =
        crate::fp_feedback::confidence_multipliers_batch(&state.app_pool, auth.tenant_id, &conf_pairs)
            .await;

    let mut out = Vec::new();
    for r in rows {
        let raw_id = r.try_get::<i64, _>("id").unwrap_or(0);
        let poc_sealed = r.try_get::<bool, _>("poc_sealed").unwrap_or(false);
        let raw_data = r.try_get::<Value, _>("raw_data").unwrap_or(Value::Null);
        let cvss = raw_data
            .get("cvss_score")
            .and_then(Value::as_f64)
            .unwrap_or(0.0);
        let mitre = raw_data
            .get("mitre_attack")
            .and_then(Value::as_str)
            .unwrap_or("")
            .to_string();
        let remediation = raw_data
            .get("remediation")
            .and_then(Value::as_str)
            .unwrap_or("")
            .to_string();
        let target = raw_data
            .get("target")
            .and_then(Value::as_str)
            .unwrap_or("")
            .to_string();
        let compliance = raw_data
            .get("compliance")
            .cloned()
            .unwrap_or(Value::Array(vec![]));
        let epss_score = r.try_get::<Option<f32>, _>("epss_score").ok().flatten();
        let epss_percentile = r.try_get::<Option<f32>, _>("epss_percentile").ok().flatten();
        let kev = r.try_get::<bool, _>("kev_listed").unwrap_or(false);
        let kev_ransom = r.try_get::<bool, _>("kev_known_ransomware").unwrap_or(false);
        let kev_due = r
            .try_get::<Option<chrono::NaiveDate>, _>("kev_due_date")
            .ok()
            .flatten()
            .map(|d| d.to_string());
        let cluster_id = r.try_get::<Option<i64>, _>("cluster_id").ok().flatten();
        let signature_hash = r.try_get::<Option<String>, _>("signature_hash").ok().flatten();
        let seen_count = r.try_get::<i32, _>("seen_count").unwrap_or(1);

        // Apply the FP/TP confidence multiplier to risk_score so a chronically-FP
        // engine gets pushed down in the prioritised list, while a high-EPSS or KEV
        // finding gets boosted. This makes the inbox automatically self-tuning.
        let base_risk = if cvss > 0.0 { cvss } else { severity_to_score(&r.try_get::<String, _>("severity").unwrap_or_default()) };
        let mut risk = base_risk;
        if let Some(s) = epss_score {
            risk *= 1.0 + (s as f64) * 0.5; // up to +50% for max EPSS
        }
        if kev {
            risk *= 1.4;
        }
        if kev_ransom {
            risk *= 1.15;
        }
        // confidence multiplier (FP/TP) — prefer persisted column, else batch map.
        let stored_conf = r.try_get::<Option<f64>, _>("confidence_multiplier").ok().flatten();
        let conf_mult = match signature_hash.as_deref() {
            Some(sig) if !sig.is_empty() => stored_conf.unwrap_or_else(|| {
                let eng = r.try_get::<String, _>("source").unwrap_or_default();
                *conf_map.get(&(eng, sig.to_string())).unwrap_or(&1.0)
            }),
            _ => stored_conf.unwrap_or(1.0),
        };
        let stored_effective = r.try_get::<Option<f64>, _>("effective_risk").ok().flatten();
        risk *= conf_mult;
        let risk = stored_effective.unwrap_or_else(|| (risk.min(10.0) * 10.0).round() / 10.0);

        // Tamper-evident attestation: re-derive the digest from the stored fields and
        // verify it against the stored receipt. attestation_valid=false means the row
        // was altered out-of-band since it was recorded (or predates attestation).
        let fid = r.try_get::<String, _>("finding_id").unwrap_or_default();
        let att_title = r.try_get::<String, _>("title").unwrap_or_default();
        let att_sev = r.try_get::<String, _>("severity").unwrap_or_default();
        let att_receipt = raw_data
            .get("attestation")
            .and_then(|a| a.get("receipt"))
            .and_then(Value::as_str)
            .unwrap_or("");
        let attested = !att_receipt.is_empty();
        let attestation_valid = attested
            && crate::finding_attestation::verify_finding(
                &fid, &att_title, &att_sev, &target, "", att_receipt,
            );

        out.push(json!({
            "id": format!("VLN-{}", raw_id),
            "raw_id": raw_id,
            "finding_id": fid,
            "title": r.try_get::<String, _>("title").unwrap_or_else(|_| "Finding".to_string()),
            "source": r.try_get::<String, _>("source").unwrap_or_else(|_| "NVD".to_string()),
            "severity": r.try_get::<String, _>("severity").unwrap_or_else(|_| "MEDIUM".to_string()),
            "status": r.try_get::<String, _>("status").unwrap_or_else(|_| "OPEN".to_string()),
            "client_id": r.try_get::<String, _>("client_id").unwrap_or_default(),
            "client": r.try_get::<String, _>("client_id").unwrap_or_default(),
            "description": r.try_get::<String, _>("description").unwrap_or_default(),
            "discovered_at": r.try_get::<chrono::DateTime<Utc>, _>("discovered_at").ok().map(|d| d.to_rfc3339()),
            "poc_sealed": poc_sealed,
            "verified": poc_sealed,
            "poc_commitment_sha256": r.try_get::<String, _>("poc_commitment_sha256").unwrap_or_default(),
            "cvss_score": cvss,
            "risk_score": risk,
            "effective_risk": risk,
            "priority_score": risk,
            "confidence_multiplier": conf_mult,
            "attested": attested,
            "attestation_valid": attestation_valid,
            "live_verification": raw_data.get("live_verification").cloned().unwrap_or(Value::Null),
            "live_verdict": raw_data
                .get("live_verification")
                .and_then(|v| v.get("verdict"))
                .and_then(Value::as_str)
                .unwrap_or(""),
            "mitre_attack": mitre,
            "remediation": remediation,
            "target": target,
            "compliance": compliance,
            "epss_score": epss_score,
            "epss_percentile": epss_percentile,
            "kev_listed": kev,
            "kev_known_ransomware": kev_ransom,
            "kev_due_date": kev_due,
            "intel_enriched_at": r.try_get::<Option<chrono::DateTime<Utc>>, _>("intel_enriched_at").ok().flatten().map(|d| d.to_rfc3339()),
            "cluster_id": cluster_id,
            "signature_hash": signature_hash,
            "seen_count": seen_count,
            "raw": raw_data,
        }));
    }
    (
        StatusCode::OK,
        Json(json!({
            "ok": true,
            "findings": out,
            "total": total,
            "limit": limit,
            "offset": offset,
        })),
    )
        .into_response()
}

fn severity_to_score(sev: &str) -> f64 {
    match sev.trim().to_ascii_lowercase().as_str() {
        "critical" => 9.5,
        "high" => 7.5,
        "medium" => 5.0,
        "low" => 3.0,
        "info" => 1.0,
        _ => 0.0,
    }
}

async fn api_config_public(Extension(auth): Extension<AuthContext>) -> Response {
    let region = std::env::var("WEISSMAN_REGION").unwrap_or_else(|_| "EU-West".to_string());
    let version = env!("CARGO_PKG_VERSION");
    (StatusCode::OK, Json(json!({
        "region": region,
        "version": version,
        "tenant_id": auth.tenant_id,
    }))).into_response()
}

async fn api_engines_production() -> Response {
    let ids = weissman_core::models::engine::production_engine_ids();
    let live_count = ids.len();
    (StatusCode::OK, Json(json!({
        "production": ids,
        "production_count": live_count,
        "catalog_count": 0,
        "all_runnable": true,
        "frontend_total": live_count,
    }))).into_response()
}

/// Honest engine accounting: advertised IDs vs distinct probe implementations vs aliases.
async fn api_engines_accounting() -> Response {
    (StatusCode::OK, Json(crate::engine_accounting::to_json())).into_response()
}

/// Per-engine reality classification (real_probe / alias / agent_required / special) for the
/// catalog "indication on each engine" badge.
async fn api_engines_capabilities() -> Response {
    (StatusCode::OK, Json(crate::engine_capabilities::to_json())).into_response()
}

/// Capability-based UI manifests for morphing engine C2 chrome (signed provenance envelope).
async fn api_engines_ui_manifests() -> Response {
    (StatusCode::OK, Json(crate::engine_ui_manifest::to_json())).into_response()
}

/// Resolve a single route manifest (query: `path=/ast-fuzzing`).
async fn api_engines_ui_manifest_by_route(
    axum::extract::Query(params): axum::extract::Query<std::collections::HashMap<String, String>>,
) -> Response {
    let path = params.get("path").map(String::as_str).unwrap_or("/");
    (StatusCode::OK, Json(crate::engine_ui_manifest::to_json_by_route(path))).into_response()
}

/// Ephemeral HMAC verify material for authenticated forensic UI (WASM provenance layer).
async fn api_forensic_provenance_key(Extension(auth): Extension<AuthContext>) -> Response {
    let _ = auth;
    match crate::engine_capabilities::provenance_signing_secret() {
        Some(key) => (
            StatusCode::OK,
            Json(serde_json::json!({
                "ok": true,
                "verify_key": key,
                "algorithm": "HMAC-SHA256",
            })),
        )
            .into_response(),
        None => (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(serde_json::json!({
                "ok": false,
                "detail": "UI provenance signing not configured"
            })),
        )
            .into_response(),
    }
}

/// Full engine + module onboarding requirements catalog (generated from live source).
async fn api_engines_requirements() -> Response {
    (StatusCode::OK, Json(crate::engine_requirements::catalog_json())).into_response()
}

/// Tenant-level prerequisites (LLM, OAST, AI entitlement) for onboarding wizard.
async fn api_onboarding_tenant_status(
    State(state): State<Arc<AppState>>,
    Extension(auth): Extension<AuthContext>,
) -> Response {
    let facts = tenant_onboarding_facts(state.app_pool.as_ref(), auth.tenant_id).await;
    (StatusCode::OK, Json(facts)).into_response()
}

/// Client readiness vs selected engagement modules (live field checks, no fake scores).
async fn api_clients_readiness(
    State(state): State<Arc<AppState>>,
    Extension(auth): Extension<AuthContext>,
    Path(id): Path<i64>,
    Query(q): Query<std::collections::HashMap<String, String>>,
) -> Response {
    let modules: Vec<String> = q
        .get("modules")
        .map(|s| {
            s.split(',')
                .map(|x| x.trim().to_string())
                .filter(|x| !x.is_empty())
                .collect()
        })
        .unwrap_or_default();

    let Ok(mut tx) = db::begin_tenant_tx(&state.app_pool, auth.tenant_id).await else {
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(json!({"ok": false, "detail": "Database unavailable"})),
        )
            .into_response();
    };

    let row = sqlx::query(
        r#"SELECT id, name, domains, ip_ranges, contact_email,
            COALESCE(aws_cross_account_role_arn,'') AS aws_cross_account_role_arn,
            COALESCE(aws_external_id,'') AS aws_external_id,
            COALESCE(gcp_project_id,'') AS gcp_project_id,
            COALESCE(NULLIF(trim(client_configs), ''), $2) AS client_configs
           FROM clients WHERE id = $1"#,
    )
    .bind(id)
    .bind(DEFAULT_CLIENT_CONFIGS_JSON)
    .fetch_optional(&mut *tx)
    .await
    .ok()
    .flatten();

    let agents_online: i64 = sqlx::query_scalar(
        r#"SELECT COUNT(*)::bigint FROM endpoint_agents
           WHERE tenant_id = $1 AND client_id = $2
             AND last_seen_at > now() - interval '15 minutes'"#,
    )
    .bind(auth.tenant_id)
    .bind(id)
    .fetch_one(&mut *tx)
    .await
    .unwrap_or(0);

    let _ = tx.commit().await;

    let Some(r) = row else {
        return (
            StatusCode::NOT_FOUND,
            Json(json!({"ok": false, "detail": "client not found"})),
        )
            .into_response();
    };

    let config_str: String = r.try_get("client_configs").unwrap_or_default();
    let config_val: Value = serde_json::from_str(&config_str).unwrap_or(json!({}));

    let mut client_snapshot = json!({
        "id": r.try_get::<i64,_>("id").ok(),
        "name": r.try_get::<String,_>("name").ok(),
        "domains": r.try_get::<String,_>("domains").ok(),
        "ip_ranges": r.try_get::<String,_>("ip_ranges").ok(),
        "contact_email": r.try_get::<String,_>("contact_email").ok(),
        "aws_cross_account_role_arn": r.try_get::<String,_>("aws_cross_account_role_arn").ok(),
        "aws_external_id": r.try_get::<String,_>("aws_external_id").ok(),
        "gcp_project_id": r.try_get::<String,_>("gcp_project_id").ok(),
        "client_configs": config_val,
        "onboarding": config_val.get("onboarding").cloned().unwrap_or(json!({})),
        "agents_online": agents_online,
    });

    if let Some(obj) = client_snapshot.as_object_mut() {
        if let Some(onb) = config_val.get("onboarding") {
            obj.insert("onboarding".to_string(), onb.clone());
        }
        if config_val.get("industrial_ot_enabled").is_some() {
            if let Some(cc) = obj.get_mut("client_configs") {
                if let Some(m) = cc.as_object_mut() {
                    m.insert(
                        "industrial_ot_enabled".to_string(),
                        config_val
                            .get("industrial_ot_enabled")
                            .cloned()
                            .unwrap_or(json!(false)),
                    );
                }
            }
        }
    }

    let module_ids = if modules.is_empty() {
        config_val
            .get("engagement_modules")
            .and_then(Value::as_array)
            .map(|a| {
                a.iter()
                    .filter_map(|v| v.as_str().map(str::to_string))
                    .collect::<Vec<_>>()
            })
            .unwrap_or_default()
    } else {
        modules
    };

    let tenant = tenant_onboarding_facts(state.app_pool.as_ref(), auth.tenant_id).await;
    let report = crate::engine_requirements::readiness_report(&client_snapshot, &tenant, &module_ids);

    (
        StatusCode::OK,
        Json(json!({
            "client_id": id,
            "tenant": tenant,
            "readiness": report,
        })),
    )
        .into_response()
}

async fn tenant_onboarding_facts(pool: &PgPool, tenant_id: i64) -> Value {
    let llm_env = std::env::var("WEISSMAN_LLM_BASE_URL")
        .ok()
        .filter(|s| !s.trim().is_empty());
    let oast_env = std::env::var("WEISSMAN_OAST_LISTENER_URL")
        .ok()
        .filter(|s| !s.trim().is_empty());

    let mut llm_configured = llm_env.is_some();
    let mut oast_configured = oast_env.is_some();
    let mut ai_heavy_entitled = true;
    let mut oast_listener_url = oast_env.clone().unwrap_or_default();
    let mut oast_domain = std::env::var("WEISSMAN_OAST_DOMAIN")
        .or_else(|_| std::env::var("WEISSMAN_OAST_BASE_DOMAIN"))
        .unwrap_or_default();
    let mut oast_api_key_configured = std::env::var("WEISSMAN_OAST_API_KEY")
        .ok()
        .filter(|s| !s.trim().is_empty())
        .is_some();

    if let Ok(mut tx) = db::begin_tenant_tx(pool, tenant_id).await {
        async fn cfg_val(
            tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
            tenant_id: i64,
            key: &str,
        ) -> Option<String> {
            sqlx::query_scalar::<_, String>(
                "SELECT value FROM system_configs WHERE tenant_id = $1 AND key = $2",
            )
            .bind(tenant_id)
            .bind(key)
            .fetch_optional(&mut **tx)
            .await
            .ok()
            .flatten()
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
        }

        let llm_db = cfg_val(&mut tx, tenant_id, "llm_base_url").await;
        if llm_db.is_some() {
            llm_configured = true;
        }

        if let Some(u) = cfg_val(&mut tx, tenant_id, "oast_listener_url").await {
            oast_configured = true;
            oast_listener_url = u;
        }
        if let Some(d) = cfg_val(&mut tx, tenant_id, "oast_domain").await {
            oast_configured = true;
            oast_domain = d;
        }
        let oast_db_key = cfg_val(&mut tx, tenant_id, "oast_api_key").await;
        if oast_db_key.is_some() {
            oast_api_key_configured = true;
        }

        if let Some(raw) = cfg_val(&mut tx, tenant_id, "ai_heavy_entitled").await {
            ai_heavy_entitled = !matches!(
                raw.trim().to_ascii_lowercase().as_str(),
                "false" | "0" | "no"
            );
        }
        let _ = tx.commit().await;
    }

    json!({
        "llm_configured": llm_configured,
        "oast_configured": oast_configured,
        "ai_heavy_entitled": ai_heavy_entitled,
        "oast_listener_url": oast_listener_url,
        "oast_domain": oast_domain,
        "oast_api_key_configured": oast_api_key_configured,
    })
}

/// Full tunable-parameter schema for Nexus Sovereign Swarm (NSSI) — GUI contract.
async fn api_nssi_config_schema() -> Response {
    (
        StatusCode::OK,
        Json(crate::nexus_sovereign_swarm_engine::nssi_config_schema()),
    )
        .into_response()
}

/// Live per-engine run telemetry (total runs, self-heal/recovered, failures, last status/latency)
/// for the Engine Reliability view.
async fn api_engines_telemetry() -> Response {
    (StatusCode::OK, Json(crate::engine_telemetry::to_json())).into_response()
}

const TOP_TIER_ENGINES: &[&str] = &[
    "kill_chain",
    "oast_oob",
    "deception_honeypot",
    "digital_twin",
    "zero_day_prediction",
    "threat_emulation",
    "poe_synthesis",
    "satellite_recon",
    "darkweb_intel",
    "financial_osint",
    "blockchain_trace",
    "metadata_harvest",
    "patent_recon",
    "telecom_osint",
    "iot_shodan_scan",
    "job_posting_osint",
    "github_secret_scan",
    "graphql_deep_attack",
    "grpc_reflection_attack",
    "http2_attack",
];

fn is_top_tier_engine(engine_id: &str) -> bool {
    TOP_TIER_ENGINES.iter().any(|&e| e == engine_id)
}

fn top_tier_execution_path(engine_id: &str) -> &'static str {
    if engine_id == "poe_synthesis" {
        "poe_synthesis_run"
    } else if weissman_core::models::engine::is_production_engine_id(engine_id) {
        if weissman_core::models::engine::is_engine_alias(engine_id) {
            "alias_engine_runner"
        } else {
            "command_center_engine"
        }
    } else {
        "catalog_only"
    }
}

fn top_tier_audit_row(engine_id: &str) -> Value {
    let canonical = weissman_core::models::engine::resolve_engine_id(engine_id);
    let known = weissman_core::models::engine::is_known_engine_id(engine_id);
    let production = weissman_core::models::engine::is_production_engine_id(engine_id);
    let alias = canonical != engine_id;

    json!({
        "engine_id": engine_id,
        "known_in_catalog": known,
        "canonical_engine": canonical,
        "is_alias": alias,
        "is_production_runnable": production,
        "execution_path": top_tier_execution_path(engine_id),
        "ui_route": format!("/command-center/engines/top-tier/{}", engine_id),
        "detail_route": format!("/command-center/engines/{}", engine_id),
    })
}

async fn api_engines_top_tier_audit() -> Response {
    let rows: Vec<Value> = TOP_TIER_ENGINES
        .iter()
        .map(|engine_id| top_tier_audit_row(engine_id))
        .collect();

    let connected = rows
        .iter()
        .filter(|r| {
            r.get("execution_path")
                .and_then(Value::as_str)
                .map(|p| p != "catalog_only")
                .unwrap_or(false)
        })
        .count();

    (
        StatusCode::OK,
        Json(json!({
            "top_tier_count": TOP_TIER_ENGINES.len(),
            "connected_count": connected,
            "fully_connected": connected == TOP_TIER_ENGINES.len(),
            "engines": rows,
        })),
    )
        .into_response()
}

#[derive(Deserialize)]
struct TopTierHealthProbeBody {
    target: Option<String>,
    client_id: Option<i64>,
}

#[derive(Deserialize)]
struct TopTierHistoryQuery {
    limit: Option<i64>,
}

#[derive(Deserialize)]
struct TopTierExportQuery {
    limit: Option<i64>,
    job_id: Option<String>,
}

#[derive(Deserialize)]
struct EngineHistoryQuery {
    limit: Option<i64>,
}

#[derive(Deserialize)]
struct EngineExportQuery {
    limit: Option<i64>,
    job_id: Option<String>,
}

async fn resolve_probe_target_from_client(
    pool: &PgPool,
    tenant_id: i64,
    client_id: i64,
) -> Option<String> {
    let Ok(mut tx) = db::begin_tenant_tx(pool, tenant_id).await else {
        return None;
    };
    let domains: Option<String> = sqlx::query_scalar(
        "SELECT domains FROM clients WHERE tenant_id = $1 AND id = $2",
    )
    .bind(tenant_id)
    .bind(client_id)
    .fetch_optional(&mut *tx)
    .await
    .ok()
    .flatten();
    let _ = tx.commit().await;
    let raw = domains?;
    let parsed = serde_json::from_str::<Vec<String>>(&raw).ok()?;
    let first = parsed.into_iter().find(|s| !s.trim().is_empty())?;
    if first.starts_with("http://") || first.starts_with("https://") {
        Some(first)
    } else {
        Some(format!("https://{}", first))
    }
}

async fn api_top_tier_health_probe_start(
    State(state): State<Arc<AppState>>,
    Extension(auth): Extension<AuthContext>,
    body: axum::extract::Json<TopTierHealthProbeBody>,
) -> Response {
    if let Err(r) = crate::rbac::require_operator(&auth) {
        return r;
    }
    if let Err(detail) =
        crate::billing::gate_scan_enqueue(state.auth_pool.as_ref(), auth.tenant_id).await
    {
        return (
            StatusCode::PAYMENT_REQUIRED,
            Json(json!({"ok": false, "detail": detail})),
        )
            .into_response();
    }
    let target_raw = body
        .target
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(str::to_string);
    let target = if let Some(t) = target_raw {
        t
    } else if let Some(cid) = body.client_id {
        match resolve_probe_target_from_client(state.app_pool.as_ref(), auth.tenant_id, cid).await {
            Some(t) => t,
            None => {
                return (
                    StatusCode::BAD_REQUEST,
                    Json(json!({"detail": "target required (or provide client_id with at least one domain)"})),
                )
                    .into_response();
            }
        }
    } else {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({"detail": "target required"})),
        )
            .into_response();
    };

    let payload = json!({
        "target": target,
        "client_id": body.client_id,
        "engines": TOP_TIER_ENGINES,
    });

    match crate::async_jobs::enqueue(
        state.app_pool.as_ref(),
        auth.tenant_id,
        "top_tier_health_probe",
        payload,
        None,
    )
    .await
    {
        Ok(job_id) => (
            StatusCode::ACCEPTED,
            Json(json!({
                "ok": true,
                "job_id": job_id.to_string(),
                "status_url": format!("/api/jobs/{}", job_id),
                "message": "Top-tier health probe queued",
            })),
        )
            .into_response(),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({"detail": scrub_internal_error(&e)})),
        )
            .into_response(),
    }
}

async fn collect_top_tier_history_json(
    state: &Arc<AppState>,
    tenant_id: i64,
    engine_id: &str,
    limit: i64,
) -> Result<Value, String> {
    let canonical = weissman_core::models::engine::resolve_engine_id(engine_id).to_string();
    let mut tx = db::begin_tenant_tx(state.app_pool.as_ref(), tenant_id)
        .await
        .map_err(|e| format!("tenant tx: {}", e))?;

    let mut jobs: Vec<Value> = Vec::new();

    let direct_rows = sqlx::query(
        r#"SELECT id, kind, status, payload, result_json, last_error, created_at, updated_at
           FROM weissman_async_jobs
           WHERE tenant_id = $1
             AND (
               (kind = 'command_center_engine' AND (payload->>'engine' = $2 OR payload->>'engine' = $3))
               OR (kind = 'poe_synthesis_run' AND $2 = 'poe_synthesis')
             )
           ORDER BY created_at DESC
           LIMIT $4"#,
    )
    .bind(tenant_id)
    .bind(engine_id)
    .bind(&canonical)
    .bind(limit.max(1).min(200))
    .fetch_all(&mut *tx)
    .await
    .map_err(|e| format!("direct jobs query: {}", e))?;

    for r in direct_rows {
        let result_json = r
            .try_get::<Option<serde_json::Value>, _>("result_json")
            .ok()
            .flatten()
            .unwrap_or_else(|| json!({}));
        let findings_count = result_json
            .get("findings")
            .and_then(Value::as_array)
            .map(|a| a.len())
            .unwrap_or(0);
        jobs.push(json!({
            "job_id": r.try_get::<uuid::Uuid,_>("id").map(|v| v.to_string()).unwrap_or_default(),
            "kind": r.try_get::<String,_>("kind").unwrap_or_default(),
            "status": r.try_get::<String,_>("status").unwrap_or_default(),
            "created_at": r.try_get::<chrono::DateTime<Utc>,_>("created_at").ok().map(|d| d.to_rfc3339()),
            "updated_at": r.try_get::<chrono::DateTime<Utc>,_>("updated_at").ok().map(|d| d.to_rfc3339()),
            "last_error": r.try_get::<Option<String>,_>("last_error").ok().flatten(),
            "findings_count": findings_count,
            "source": "engine_job",
        }));
    }

    let probe_rows = sqlx::query(
        r#"SELECT id, status, result_json, created_at, updated_at
           FROM weissman_async_jobs
           WHERE tenant_id = $1 AND kind = 'top_tier_health_probe'
           ORDER BY created_at DESC
           LIMIT 50"#,
    )
    .bind(tenant_id)
    .fetch_all(&mut *tx)
    .await
    .map_err(|e| format!("probe jobs query: {}", e))?;

    for r in probe_rows {
        let result_json = r
            .try_get::<Option<serde_json::Value>, _>("result_json")
            .ok()
            .flatten()
            .unwrap_or_else(|| json!({}));
        let probe_entries = result_json
            .get("engines")
            .and_then(Value::as_array)
            .cloned()
            .unwrap_or_default();
        for entry in probe_entries {
            let eid = entry.get("engine_id").and_then(Value::as_str).unwrap_or("");
            if eid != engine_id {
                continue;
            }
            jobs.push(json!({
                "job_id": r.try_get::<uuid::Uuid,_>("id").map(|v| v.to_string()).unwrap_or_default(),
                "kind": "top_tier_health_probe",
                "status": r.try_get::<String,_>("status").unwrap_or_default(),
                "created_at": r.try_get::<chrono::DateTime<Utc>,_>("created_at").ok().map(|d| d.to_rfc3339()),
                "updated_at": r.try_get::<chrono::DateTime<Utc>,_>("updated_at").ok().map(|d| d.to_rfc3339()),
                "last_error": Value::Null,
                "findings_count": entry.get("findings_count").and_then(Value::as_u64).unwrap_or(0),
                "probe_status": entry.get("probe_status").cloned().unwrap_or_else(|| json!("unknown")),
                "duration_ms": entry.get("duration_ms").cloned().unwrap_or_else(|| json!(0)),
                "source": "health_probe",
            }));
        }
    }

    jobs.sort_by(|a, b| {
        let ka = a
            .get("created_at")
            .and_then(Value::as_str)
            .unwrap_or("")
            .to_string();
        let kb = b
            .get("created_at")
            .and_then(Value::as_str)
            .unwrap_or("")
            .to_string();
        kb.cmp(&ka)
    });
    jobs.truncate(limit.max(1).min(200) as usize);

    let finding_rows = sqlx::query(
        r#"SELECT id, title, severity, status, source, discovered_at
           FROM vulnerabilities
           WHERE source = $1 OR source = $2
           ORDER BY discovered_at DESC
           LIMIT 120"#,
    )
    .bind(engine_id)
    .bind(&canonical)
    .fetch_all(&mut *tx)
    .await
    .map_err(|e| format!("findings query: {}", e))?;

    let _ = tx.commit().await;

    let findings: Vec<Value> = finding_rows
        .into_iter()
        .map(|r| {
            json!({
                "id": r.try_get::<i64,_>("id").unwrap_or(0),
                "title": r.try_get::<String,_>("title").unwrap_or_else(|_| "Finding".to_string()),
                "severity": r.try_get::<String,_>("severity").unwrap_or_else(|_| "medium".to_string()),
                "status": r.try_get::<String,_>("status").unwrap_or_else(|_| "OPEN".to_string()),
                "source": r.try_get::<String,_>("source").unwrap_or_default(),
                "discovered_at": r.try_get::<chrono::DateTime<Utc>,_>("discovered_at").ok().map(|d| d.to_rfc3339()),
            })
        })
        .collect();

    let audit = top_tier_audit_row(engine_id);
    Ok(json!({
        "engine_id": engine_id,
        "canonical_engine": canonical,
        "audit": audit,
        "jobs": jobs,
        "findings": findings,
        "job_count": jobs.len(),
        "finding_count": findings.len(),
    }))
}

async fn collect_engine_history_json(
    state: &Arc<AppState>,
    tenant_id: i64,
    engine_id: &str,
    limit: i64,
) -> Result<Value, String> {
    let canonical = weissman_core::models::engine::resolve_engine_id(engine_id).to_string();
    let mut tx = db::begin_tenant_tx(state.app_pool.as_ref(), tenant_id)
        .await
        .map_err(|e| format!("tenant tx: {}", e))?;

    let mut jobs: Vec<Value> = Vec::new();
    let lim = limit.max(1).min(200);

    let direct_rows = sqlx::query(
        r#"SELECT id, kind, status, payload, result_json, last_error, created_at, updated_at
           FROM weissman_async_jobs
           WHERE tenant_id = $1
             AND (
               (kind = 'command_center_engine' AND (payload->>'engine' = $2 OR payload->>'engine' = $3))
               OR (kind = 'poe_synthesis_run' AND $2 = 'poe_synthesis')
             )
           ORDER BY created_at DESC
           LIMIT $4"#,
    )
    .bind(tenant_id)
    .bind(engine_id)
    .bind(&canonical)
    .bind(lim)
    .fetch_all(&mut *tx)
    .await
    .map_err(|e| format!("direct jobs query: {}", e))?;

    for r in direct_rows {
        let payload = r
            .try_get::<Option<serde_json::Value>, _>("payload")
            .ok()
            .flatten()
            .unwrap_or_else(|| json!({}));
        let result_json = r
            .try_get::<Option<serde_json::Value>, _>("result_json")
            .ok()
            .flatten()
            .unwrap_or_else(|| json!({}));
        let findings_count = result_json
            .get("findings")
            .and_then(Value::as_array)
            .map(|a| a.len())
            .unwrap_or(0);
        let target = payload
            .get("target")
            .and_then(Value::as_str)
            .map(|s| s.to_string())
            .unwrap_or_default();
        jobs.push(json!({
            "job_id": r.try_get::<uuid::Uuid,_>("id").map(|v| v.to_string()).unwrap_or_default(),
            "kind": r.try_get::<String,_>("kind").unwrap_or_default(),
            "status": r.try_get::<String,_>("status").unwrap_or_default(),
            "created_at": r.try_get::<chrono::DateTime<Utc>,_>("created_at").ok().map(|d| d.to_rfc3339()),
            "updated_at": r.try_get::<chrono::DateTime<Utc>,_>("updated_at").ok().map(|d| d.to_rfc3339()),
            "last_error": r.try_get::<Option<String>,_>("last_error").ok().flatten(),
            "findings_count": findings_count,
            "target": target,
            "source": "engine_job",
        }));
    }

    if is_top_tier_engine(engine_id) {
        let probe_rows = sqlx::query(
            r#"SELECT id, status, result_json, created_at, updated_at
               FROM weissman_async_jobs
               WHERE tenant_id = $1 AND kind = 'top_tier_health_probe'
               ORDER BY created_at DESC
               LIMIT 50"#,
        )
        .bind(tenant_id)
        .fetch_all(&mut *tx)
        .await
        .map_err(|e| format!("probe jobs query: {}", e))?;

        for r in probe_rows {
            let result_json = r
                .try_get::<Option<serde_json::Value>, _>("result_json")
                .ok()
                .flatten()
                .unwrap_or_else(|| json!({}));
            let probe_entries = result_json
                .get("engines")
                .and_then(Value::as_array)
                .cloned()
                .unwrap_or_default();
            for entry in probe_entries {
                let eid = entry.get("engine_id").and_then(Value::as_str).unwrap_or("");
                if eid != engine_id {
                    continue;
                }
                jobs.push(json!({
                    "job_id": r.try_get::<uuid::Uuid,_>("id").map(|v| v.to_string()).unwrap_or_default(),
                    "kind": "top_tier_health_probe",
                    "status": r.try_get::<String,_>("status").unwrap_or_default(),
                    "created_at": r.try_get::<chrono::DateTime<Utc>,_>("created_at").ok().map(|d| d.to_rfc3339()),
                    "updated_at": r.try_get::<chrono::DateTime<Utc>,_>("updated_at").ok().map(|d| d.to_rfc3339()),
                    "last_error": Value::Null,
                    "findings_count": entry.get("findings_count").and_then(Value::as_u64).unwrap_or(0),
                    "probe_status": entry.get("probe_status").cloned().unwrap_or_else(|| json!("unknown")),
                    "duration_ms": entry.get("duration_ms").cloned().unwrap_or_else(|| json!(0)),
                    "source": "health_probe",
                }));
            }
        }
    }

    jobs.sort_by(|a, b| {
        let ka = a
            .get("created_at")
            .and_then(Value::as_str)
            .unwrap_or("")
            .to_string();
        let kb = b
            .get("created_at")
            .and_then(Value::as_str)
            .unwrap_or("")
            .to_string();
        kb.cmp(&ka)
    });
    jobs.truncate(lim as usize);

    let finding_rows = sqlx::query(
        r#"SELECT id, title, severity, status, source, discovered_at
           FROM vulnerabilities
           WHERE source = $1 OR source = $2
           ORDER BY discovered_at DESC
           LIMIT 180"#,
    )
    .bind(engine_id)
    .bind(&canonical)
    .fetch_all(&mut *tx)
    .await
    .map_err(|e| format!("findings query: {}", e))?;

    let _ = tx.commit().await;

    let findings: Vec<Value> = finding_rows
        .into_iter()
        .map(|r| {
            json!({
                "id": r.try_get::<i64,_>("id").unwrap_or(0),
                "title": r.try_get::<String,_>("title").unwrap_or_else(|_| "Finding".to_string()),
                "severity": r.try_get::<String,_>("severity").unwrap_or_else(|_| "medium".to_string()),
                "status": r.try_get::<String,_>("status").unwrap_or_else(|_| "OPEN".to_string()),
                "source": r.try_get::<String,_>("source").unwrap_or_default(),
                "discovered_at": r.try_get::<chrono::DateTime<Utc>,_>("discovered_at").ok().map(|d| d.to_rfc3339()),
            })
        })
        .collect();

    Ok(json!({
        "engine_id": engine_id,
        "canonical_engine": canonical,
        "jobs": jobs,
        "findings": findings,
        "job_count": jobs.len(),
        "finding_count": findings.len(),
    }))
}

async fn api_engine_history_summary(
    State(state): State<Arc<AppState>>,
    Extension(auth): Extension<AuthContext>,
) -> Response {
    match collect_engine_history_summary_json(&state, auth.tenant_id).await {
        Ok(v) => (StatusCode::OK, Json(v)).into_response(),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({"ok": false, "detail": e})),
        )
            .into_response(),
    }
}

async fn collect_engine_history_summary_json(
    state: &Arc<AppState>,
    tenant_id: i64,
) -> Result<Value, String> {
    let mut tx = db::begin_tenant_tx(state.app_pool.as_ref(), tenant_id)
        .await
        .map_err(|e| format!("tenant tx: {}", e))?;

    let rows = sqlx::query(
        r#"SELECT DISTINCT ON (engine_key)
              engine_key,
              id,
              status,
              result_json,
              created_at,
              updated_at
           FROM (
             SELECT
               COALESCE(payload->>'engine', kind) AS engine_key,
               id,
               status,
               result_json,
               created_at,
               updated_at
             FROM weissman_async_jobs
             WHERE tenant_id = $1
               AND (
                 (kind = 'command_center_engine' AND payload->>'engine' IS NOT NULL)
                 OR kind = 'poe_synthesis_run'
               )
           ) jobs
           ORDER BY engine_key, created_at DESC"#,
    )
    .bind(tenant_id)
    .fetch_all(&mut *tx)
    .await
    .map_err(|e| format!("history summary query: {}", e))?;

    let _ = tx.commit().await;

    let mut engines = serde_json::Map::new();
    for r in rows {
        let engine_id = r
            .try_get::<String, _>("engine_key")
            .unwrap_or_default();
        if engine_id.is_empty() {
            continue;
        }
        let result_json = r
            .try_get::<Option<serde_json::Value>, _>("result_json")
            .ok()
            .flatten()
            .unwrap_or_else(|| json!({}));
        let mut findings_count = result_json
            .get("findings")
            .and_then(Value::as_array)
            .map(|a| a.len())
            .unwrap_or(0);
        if findings_count == 0 {
            if let Some(n) = result_json.get("findings_count").and_then(Value::as_u64) {
                findings_count = n as usize;
            }
        }
        engines.insert(
            engine_id,
            json!({
                "job_id": r.try_get::<uuid::Uuid,_>("id").map(|v| v.to_string()).unwrap_or_default(),
                "status": r.try_get::<String,_>("status").unwrap_or_default(),
                "created_at": r.try_get::<chrono::DateTime<Utc>,_>("created_at").ok().map(|d| d.to_rfc3339()),
                "updated_at": r.try_get::<chrono::DateTime<Utc>,_>("updated_at").ok().map(|d| d.to_rfc3339()),
                "findings_count": findings_count,
            }),
        );
    }

    Ok(json!({
        "ok": true,
        "engines": engines,
        "count": engines.len(),
    }))
}

async fn api_engine_history(
    State(state): State<Arc<AppState>>,
    Extension(auth): Extension<AuthContext>,
    Path(engine_id): Path<String>,
    Query(q): Query<EngineHistoryQuery>,
) -> Response {
    let engine_id = engine_id.trim().to_string();
    if !weissman_core::models::engine::is_known_engine_id(engine_id.as_str()) {
        return (
            StatusCode::NOT_FOUND,
            Json(json!({"detail": "unknown engine"})),
        )
            .into_response();
    }
    let limit = q.limit.unwrap_or(80);
    match collect_engine_history_json(&state, auth.tenant_id, engine_id.as_str(), limit).await {
        Ok(v) => (StatusCode::OK, Json(v)).into_response(),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({"detail": e})),
        )
            .into_response(),
    }
}

async fn api_engine_export(
    State(state): State<Arc<AppState>>,
    Extension(auth): Extension<AuthContext>,
    Path(engine_id): Path<String>,
    Query(q): Query<EngineExportQuery>,
) -> Response {
    let engine_id = engine_id.trim().to_string();
    if !weissman_core::models::engine::is_known_engine_id(engine_id.as_str()) {
        return (
            StatusCode::NOT_FOUND,
            Json(json!({"detail": "unknown engine"})),
        )
            .into_response();
    }
    let limit = q.limit.unwrap_or(120);
    let mut out = match collect_engine_history_json(&state, auth.tenant_id, engine_id.as_str(), limit).await {
        Ok(v) => v,
        Err(e) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"detail": e})),
            )
                .into_response();
        }
    };

    if let Some(job_id_str) = q.job_id.as_deref().map(str::trim).filter(|s| !s.is_empty()) {
        if let Ok(job_uuid) = uuid::Uuid::parse_str(job_id_str) {
            if let Ok(Some(status)) = db::job_queue::get_job_for_tenant(
                state.app_pool.as_ref(),
                auth.tenant_id,
                job_uuid,
            )
            .await
            {
                if let Some(obj) = out.as_object_mut() {
                    obj.insert("selected_job".into(), json!(status));
                }
            }
        }
    }
    if let Some(obj) = out.as_object_mut() {
        obj.insert("exported_at".into(), json!(chrono::Utc::now().to_rfc3339()));
    }
    (StatusCode::OK, Json(out)).into_response()
}

async fn api_top_tier_engine_history(
    State(state): State<Arc<AppState>>,
    Extension(auth): Extension<AuthContext>,
    Path(engine_id): Path<String>,
    Query(q): Query<TopTierHistoryQuery>,
) -> Response {
    let engine_id = engine_id.trim().to_string();
    if !is_top_tier_engine(engine_id.as_str()) {
        return (
            StatusCode::NOT_FOUND,
            Json(json!({"detail": "unknown top-tier engine"})),
        )
            .into_response();
    }
    let limit = q.limit.unwrap_or(60);
    match collect_top_tier_history_json(&state, auth.tenant_id, engine_id.as_str(), limit).await {
        Ok(v) => (StatusCode::OK, Json(v)).into_response(),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({"detail": e})),
        )
            .into_response(),
    }
}

async fn api_top_tier_engine_export(
    State(state): State<Arc<AppState>>,
    Extension(auth): Extension<AuthContext>,
    Path(engine_id): Path<String>,
    Query(q): Query<TopTierExportQuery>,
) -> Response {
    let engine_id = engine_id.trim().to_string();
    if !is_top_tier_engine(engine_id.as_str()) {
        return (
            StatusCode::NOT_FOUND,
            Json(json!({"detail": "unknown top-tier engine"})),
        )
            .into_response();
    }
    let limit = q.limit.unwrap_or(120);
    let mut out = match collect_top_tier_history_json(&state, auth.tenant_id, engine_id.as_str(), limit).await {
        Ok(v) => v,
        Err(e) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"detail": e})),
            )
                .into_response();
        }
    };

    if let Some(job_id_str) = q.job_id.as_deref().map(str::trim).filter(|s| !s.is_empty()) {
        if let Ok(job_uuid) = uuid::Uuid::parse_str(job_id_str) {
            if let Ok(Some(status)) = db::job_queue::get_job_for_tenant(
                state.app_pool.as_ref(),
                auth.tenant_id,
                job_uuid,
            )
            .await
            {
                if let Some(obj) = out.as_object_mut() {
                    obj.insert("selected_job".into(), json!(status));
                }
            }
        }
    }

    if let Some(obj) = out.as_object_mut() {
        obj.insert("exported_at".into(), json!(chrono::Utc::now().to_rfc3339()));
    }
    (StatusCode::OK, Json(out)).into_response()
}

async fn api_reports(State(state): State<Arc<AppState>>, Extension(auth): Extension<AuthContext>) -> Response {
    let Ok(mut tx) = db::begin_tenant_tx(&state.app_pool, auth.tenant_id).await else {
        return (StatusCode::SERVICE_UNAVAILABLE, Json(Value::Array(vec![]))).into_response();
    };
    let rows = sqlx::query("SELECT id, created_at, pdf_path FROM report_runs ORDER BY created_at DESC LIMIT 100")
        .fetch_all(&mut *tx).await.unwrap_or_default();
    let _ = tx.commit().await;
    let out: Vec<Value> = rows.into_iter().map(|r| json!({
        "id": r.try_get::<i64,_>("id").unwrap_or(0),
        "created_at": r.try_get::<chrono::DateTime<Utc>,_>("created_at").ok().map(|d| d.to_rfc3339()),
        "pdf_path": r.try_get::<Option<String>,_>("pdf_path").ok().flatten(),
    })).collect();
    (StatusCode::OK, Json(Value::Array(out))).into_response()
}

/// Fixed cost-12 bcrypt hash used to equalize login timing: on the not-found /
/// empty-hash paths we still run one bcrypt verify against this, so a login for a
/// non-existent email takes the same time as one for a real user. Without it, the
/// presence/absence of the expensive verify is a user-enumeration oracle — the
/// exact timing side-channel this platform's own engine is built to detect.
/// Computed once on first use.
fn login_timing_equalizer_hash() -> &'static str {
    use std::sync::OnceLock;
    static H: OnceLock<String> = OnceLock::new();
    H.get_or_init(|| bcrypt::hash("weissman-login-timing-equalizer", 12).unwrap_or_default())
}

async fn api_login(State(state): State<Arc<AppState>>, ConnectInfo(addr): ConnectInfo<SocketAddr>, headers: HeaderMap, body: axum::extract::Json<LoginBody>) -> Response {
    let ip = extract_client_ip(&headers, addr);
    let email = body.email.trim();
    let password = body.password.as_str();
    let slug = body.tenant_slug.trim();
    let slug = if slug.is_empty() { "default" } else { slug };
    let tenant_key: i64 = match sqlx::query_scalar::<_, i64>(
        "SELECT id FROM tenants WHERE slug = $1 AND active = true LIMIT 1",
    )
    .bind(slug)
    .fetch_optional(state.auth_pool.as_ref())
    .await
    {
        Ok(Some(id)) => id,
        _ => match sqlx::query_scalar::<_, i64>(
            "SELECT id FROM tenants WHERE slug = $1 AND active = true LIMIT 1",
        )
        .bind(slug)
        .fetch_optional(state.app_pool.as_ref())
        .await
        {
            Ok(Some(id)) => id,
            _ => {
                return (
                    StatusCode::UNAUTHORIZED,
                    Json(json!({"ok": false, "detail": "Invalid email or password"})),
                )
                    .into_response();
            }
        },
    };
    if let Some(retry_after) = match crate::http::check_lockout_status(tenant_key, email).await {
        crate::http::LockoutStatus::Locked(secs) => Some(secs),
        crate::http::LockoutStatus::DistributedStoreUnavailable => {
            return crate::http::rate_limit_redis::distributed_store_unavailable_response();
        }
        crate::http::LockoutStatus::Allowed => None,
    } {
        return crate::http::locked_response(retry_after);
    }
    if let Err(e) = weissman_db::auth_access::record_auth_access(
        state.auth_pool.as_ref(),
        tenant_key,
        "password_login",
    )
    .await
    {
        tracing::warn!(
            target: "security_audit",
            error = %e,
            "audit_auth_access failed; continuing login attempt"
        );
    }
    let row = match sqlx::query(
        r#"SELECT u.id, COALESCE(u.password_hash,'') AS password_hash, u.tenant_id,
                  COALESCE(NULLIF(trim(u.role), ''), 'viewer') AS role,
                  COALESCE(u.is_superadmin, false) AS is_superadmin,
                  COALESCE(u.mfa_enabled, false) AS mfa_enabled
           FROM auth.v_user_lookup u
           WHERE u.tenant_id = $1 AND lower(trim(u.email)) = lower(trim($2)) AND u.is_active = true"#,
    )
    .bind(tenant_key)
    .bind(email)
    .fetch_optional(state.auth_pool.as_ref())
    .await
    {
        Ok(v) => (v, false),
        Err(e) => {
            tracing::warn!(target: "auth", error = %e, "auth_pool user lookup failed; falling back to app_pool (MFA fail-closed)");
            let Ok(mut tx) = db::begin_tenant_tx(&state.app_pool, tenant_key).await else {
                return (
                    StatusCode::SERVICE_UNAVAILABLE,
                    Json(json!({
                        "ok": false,
                        "detail": "Authentication service temporarily unavailable",
                        "code": "auth_degraded"
                    })),
                )
                    .into_response();
            };
            let fallback = sqlx::query(
                r#"SELECT u.id, COALESCE(u.password_hash,'') AS password_hash, u.tenant_id,
                          COALESCE(NULLIF(trim(u.role), ''), 'viewer') AS role,
                          COALESCE(u.is_superadmin, false) AS is_superadmin,
                          COALESCE(u.mfa_enabled, false) AS mfa_enabled
                   FROM users u
                   WHERE u.tenant_id = $1 AND lower(trim(u.email)) = lower(trim($2)) AND u.is_active = true"#,
            )
            .bind(tenant_key)
            .bind(email)
            .fetch_optional(&mut *tx)
            .await
            .ok()
            .flatten();
            let _ = tx.commit().await;
            (fallback, true)
        }
    };
    let auth_pool_degraded = row.1;
    let row = row.0;
    let (user_id, hash, tenant_id, role, is_superadmin, mfa_enabled) = match row {
        Some(r) => (
            r.try_get::<i64, _>("id").unwrap_or(0),
            r.try_get::<String, _>("password_hash").unwrap_or_default(),
            r.try_get::<i64, _>("tenant_id").unwrap_or(0),
            r.try_get::<String, _>("role").unwrap_or_else(|_| "viewer".into()),
            r.try_get::<bool, _>("is_superadmin").unwrap_or(false),
            r.try_get::<bool, _>("mfa_enabled").unwrap_or(false),
        ),
        None => {
            // Constant-time: burn one bcrypt verify so a non-existent email costs
            // the same as a real one (no user-enumeration by response timing).
            let _ = bcrypt::verify(password, login_timing_equalizer_hash());
            crate::audit_log::record_login_failure_audit(
                state.app_pool.as_ref(),
                tenant_key,
                email,
                &ip,
                "unknown user",
            )
            .await;
            crate::http::record_failure(tenant_key, email).await;
            return (StatusCode::UNAUTHORIZED, Json(json!({"ok": false, "detail": "Invalid email or password"}))).into_response();
        }
    };
    if hash.is_empty() {
        // Constant-time equalizer (see above): an account with no stored hash must
        // not be distinguishable from a real one by timing either.
        let _ = bcrypt::verify(password, login_timing_equalizer_hash());
        crate::audit_log::record_login_failure_audit(
            state.app_pool.as_ref(),
            tenant_key,
            email,
            &ip,
            "empty password hash",
        )
        .await;
        crate::http::record_failure(tenant_key, email).await;
        return (StatusCode::UNAUTHORIZED, Json(json!({"ok": false, "detail": "Invalid email or password"}))).into_response();
    }
    let mut password_ok = matches!(bcrypt::verify(password, &hash), Ok(true));
    if !password_ok
        && !weissman_core::tls_policy::is_production_environment()
        && matches!(
            std::env::var("WEISSMAN_ALLOW_DEFAULT_ADMIN_PASSWORD").as_deref(),
            Ok("1") | Ok("true") | Ok("yes")
        )
        && password == "changeme"
    {
        tracing::warn!(target: "auth", email = %email, "dev fallback password accepted");
        password_ok = true;
    }

    if password_ok {
            if auth_pool_degraded && !mfa_enabled {
                tracing::warn!(
                    target: "auth",
                    user_id,
                    tenant_id,
                    "auth_pool degraded; refusing password-only login without verified MFA status"
                );
                return (
                    StatusCode::SERVICE_UNAVAILABLE,
                    Json(json!({
                        "ok": false,
                        "detail": "Authentication service temporarily unavailable; cannot verify MFA status",
                        "code": "auth_degraded"
                    })),
                )
                    .into_response();
            }
            // ── BLOCKER #3: Tenant-wide MFA enforcement ─────────────────────
            // If tenant policy `mfa_required` is true, deny login when MFA
            // is not yet enrolled. If the user has MFA, always go through
            // /api/auth/mfa/verify (no shortcut even if mfa_required=false).
            let tenant_requires_mfa = match db::begin_tenant_tx(&state.app_pool, tenant_id).await {
                Ok(mut tx) => {
                    let v: Option<String> = sqlx::query_scalar(
                        "SELECT value FROM system_configs WHERE tenant_id = $1 AND key = 'mfa_required'",
                    )
                    .bind(tenant_id)
                    .fetch_optional(&mut *tx)
                    .await
                    .ok()
                    .flatten();
                    let _ = tx.commit().await;
                    matches!(v.as_deref().map(str::trim), Some("true") | Some("1") | Some("yes"))
                }
                Err(_) => false,
            };
            if tenant_requires_mfa && !mfa_enabled {
                tracing::warn!(target: "auth", user_id, tenant_id, "MFA required by tenant policy but user has not enrolled");
                return (
                    StatusCode::FORBIDDEN,
                    Json(json!({
                        "ok": false,
                        "mfa_enrollment_required": true,
                        "detail": "MFA enrollment required by tenant policy. Sign in via the legacy console once to enroll, then retry.",
                        "code": "mfa_enrollment_required"
                    })),
                )
                    .into_response();
            }
            if mfa_enabled {
                let mfa_token = match crate::auth_jwt::create_mfa_pending_token(
                    user_id,
                    tenant_id,
                    &role,
                    is_superadmin,
                ) {
                    Ok(t) => t,
                    Err(_) => {
                        return (
                            StatusCode::INTERNAL_SERVER_ERROR,
                            Json(json!({"ok": false, "detail": "MFA session failed"})),
                        )
                            .into_response();
                    }
                };
                return (
                    StatusCode::OK,
                    Json(json!({
                        "ok": false,
                        "mfa_required": true,
                        "mfa_token": mfa_token,
                        "detail": "Enter authenticator code",
                    })),
                )
                    .into_response();
            }
            let mut tx = match db::begin_tenant_tx(&state.app_pool, tenant_id).await { Ok(t) => t, Err(_) => return (StatusCode::SERVICE_UNAVAILABLE, Json(json!({"ok": false}))).into_response() };
            let _ = audit_log::insert_audit(&mut tx, tenant_id, Some(user_id), email, "login", "session created", &ip).await;
            let _ = tx.commit().await;
            let binding = crate::auth_jwt::StreamBinding::from_http(&headers, addr);
            let (access_jwt, access_cookie, refresh_cookie) = match crate::auth_refresh::build_session_cookie_headers(state.auth_pool.as_ref(), user_id, tenant_id, &binding).await {
                Ok(p) => p,
                Err(e) => {
                    tracing::error!(target: "auth", error = %e, "login session cookie build failed");
                    return (StatusCode::INTERNAL_SERVER_ERROR, Json(json!({"ok": false, "detail": "session issuance failed"}))).into_response();
                }
            };
            tracing::debug!(target: "auth", user_id, tenant_id, "login ok");
            let mut response = (
                StatusCode::OK,
                Json(json!({
                    "ok": true,
                    "user_id": user_id,
                    "tenant_id": tenant_id,
                    "role": role,
                    "is_superadmin": is_superadmin,
                    "access_token": access_jwt,
                })),
            )
                .into_response();
            crate::http::clear_failures(tenant_id, email).await;
            append_set_cookie(response.headers_mut(), &access_cookie);
            append_set_cookie(response.headers_mut(), &refresh_cookie);
            response
        } else {
            crate::audit_log::record_login_failure_audit(
                state.app_pool.as_ref(),
                tenant_key,
                email,
                &ip,
                "invalid password",
            )
            .await;
            crate::http::record_failure(tenant_key, email).await;
            (StatusCode::UNAUTHORIZED, Json(json!({"ok": false, "detail": "Invalid email or password"}))).into_response()
        }
}
