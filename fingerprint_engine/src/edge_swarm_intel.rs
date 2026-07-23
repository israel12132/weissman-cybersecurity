//! Edge swarm registry: smart proximity selection (vLLM + deterministic fallback) for scan payloads
//! and orchestrator telemetry. Respects RLS via `begin_tenant_tx` for all reads.
//! Node `metadata` JSON may carry operator-defined egress hints; client fingerprint rotation for fuzz
//! probes uses [`crate::fuzz_http_pool::ghost_swarm_sequence`] (optional XOR with `edge_swarm_node_id`).

use serde_json::{json, Value};
use sqlx::{Postgres, Row, Transaction};

#[derive(Debug, Clone)]
struct EdgeNodeRow {
    id: i64,
    region_code: String,
    pop_label: String,
    active_jobs: i32,
    latitude: Option<f64>,
    longitude: Option<f64>,
}

async fn load_edge_nodes_tx(
    tx: &mut Transaction<'_, Postgres>,
    tenant_id: i64,
) -> Result<Vec<EdgeNodeRow>, sqlx::Error> {
    let rows = sqlx::query(
        r#"SELECT id, region_code, pop_label, active_jobs, latitude, longitude
           FROM edge_swarm_nodes WHERE tenant_id = $1"#,
    )
    .bind(tenant_id)
    .fetch_all(&mut **tx)
    .await?;
    let mut out = Vec::new();
    for r in rows {
        out.push(EdgeNodeRow {
            id: r.try_get::<i64, _>("id").unwrap_or(0),
            region_code: r.try_get::<String, _>("region_code").unwrap_or_default(),
            pop_label: r.try_get::<String, _>("pop_label").unwrap_or_default(),
            active_jobs: r.try_get::<i32, _>("active_jobs").unwrap_or(0),
            latitude: r.try_get::<Option<f64>, _>("latitude").ok().flatten(),
            longitude: r.try_get::<Option<f64>, _>("longitude").ok().flatten(),
        });
    }
    Ok(out)
}

fn target_region_guess(target: &str) -> Option<&'static str> {
    let t = target.to_lowercase();
    if t.contains("eu-west")
        || t.contains("eu-central")
        || t.contains("frankfurt")
        || t.contains("ireland")
        || t.contains(".de/")
        || t.contains(".fr/")
    {
        return Some("eu");
    }
    if t.contains("ap-")
        || t.contains("tokyo")
        || t.contains("singapore")
        || t.contains("sydney")
        || t.contains(".jp/")
        || t.contains(".au/")
    {
        return Some("ap");
    }
    if t.contains("us-east")
        || t.contains("us-west")
        || t.contains("virginia")
        || t.contains("oregon")
        || t.contains(".us/")
    {
        return Some("us");
    }
    None
}

/// Prefer matching `region_code` prefix, then lowest `active_jobs`, then stable id.
fn deterministic_pick<'a>(nodes: &'a [EdgeNodeRow], target: &str) -> Option<&'a EdgeNodeRow> {
    if nodes.is_empty() {
        return None;
    }
    let hint = target_region_guess(target);
    let mut scored: Vec<(&EdgeNodeRow, i32)> = nodes
        .iter()
        .map(|n| {
            let mut score = n.active_jobs.saturating_mul(100);
            if let Some(h) = hint {
                let rc = n.region_code.to_lowercase();
                if rc.starts_with(h) || rc.contains(h) {
                    score -= 50;
                }
            }
            (n, score)
        })
        .collect();
    scored.sort_by(|a, b| a.1.cmp(&b.1).then_with(|| a.0.id.cmp(&b.0.id)));
    scored.first().map(|(n, _)| *n)
}

fn parse_llm_node_id(text: &str) -> Option<i64> {
    let t = text.trim();
    let start = t.find('{')?;
    let end = t.rfind('}')?;
    let slice = t.get(start..=end)?;
    let v: Value = serde_json::from_str(slice).ok()?;
    v.get("node_id")
        .or_else(|| v.get("chosen_node_id"))
        .and_then(|x| x.as_i64())
        .or_else(|| {
            v.get("node_id")
                .and_then(|x| x.as_str())
                .and_then(|s| s.parse().ok())
        })
}

async fn llm_pick_node_id(
    nodes: &[EdgeNodeRow],
    target: &str,
    llm_base_url: &str,
    llm_model: &str,
    llm_tenant_id: Option<i64>,
) -> Option<i64> {
    if nodes.is_empty() || llm_base_url.trim().is_empty() {
        return None;
    }
    let catalog: Value = Value::Array(
        nodes
            .iter()
            .map(|n| {
                json!({
                    "node_id": n.id,
                    "region_code": n.region_code,
                    "pop_label": n.pop_label,
                    "active_jobs": n.active_jobs,
                    "latitude": n.latitude,
                    "longitude": n.longitude,
                })
            })
            .collect(),
    );
    let user = format!(
        "Scan target (URL, hostname, or IP):\n{}\n\nEdge nodes (JSON array):\n{}\n\n\
         Choose the single best node to minimize latency and geo friction: prefer region proximity to the target, then lowest active_jobs.\n\
         Output ONLY a JSON object: {{\"node_id\": <integer>}} — no markdown.",
        target,
        serde_json::to_string_pretty(&catalog).unwrap_or_else(|_| "[]".into())
    );
    let client = weissman_engines::openai_chat::llm_http_client(45);
    let model = weissman_engines::openai_chat::resolve_llm_model(llm_model);
    let text = weissman_engines::openai_chat::chat_completion_text(
        &client,
        llm_base_url,
        model.as_str(),
        Some("You assign edge scan egress for authorized security testing. Output only the requested JSON."),
        &user,
        0.1,
        256,
        llm_tenant_id,
        "edge_swarm_proximity",
        false,
    )
    .await
    .ok()?;
    let id = parse_llm_node_id(&text)?;
    if nodes.iter().any(|n| n.id == id) {
        Some(id)
    } else {
        None
    }
}

/// Build assignment JSON for job payloads / telemetry (vLLM when possible, else deterministic).
pub async fn resolve_edge_swarm_for_target(
    pool: sqlx::PgPool,
    tenant_id: i64,
    target: &str,
    llm_base_url: &str,
    llm_model: &str,
    llm_tenant_id: Option<i64>,
) -> Option<Value> {
    let mut tx = match crate::db::begin_tenant_tx(&pool, tenant_id).await {
        Ok(t) => t,
        Err(_) => return None,
    };
    let nodes = load_edge_nodes_tx(&mut tx, tenant_id).await.ok()?;
    let _ = tx.commit().await;
    if nodes.is_empty() {
        return None;
    }
    let chosen_id = llm_pick_node_id(&nodes, target, llm_base_url, llm_model, llm_tenant_id)
        .await
        .or_else(|| deterministic_pick(&nodes, target).map(|n| n.id))?;
    let n = nodes.iter().find(|x| x.id == chosen_id)?;
    Some(json!({
        "edge_swarm_node_id": n.id,
        "edge_swarm_region_code": n.region_code,
        "edge_swarm_pop_label": n.pop_label,
        "edge_swarm_active_jobs": n.active_jobs,
    }))
}

async fn load_llm_tenant_config(pool: &sqlx::PgPool, tenant_id: i64) -> Option<(String, String)> {
    let mut tx = crate::db::begin_tenant_tx(pool, tenant_id).await.ok()?;
    let base_row = sqlx::query(
        "SELECT value FROM system_configs WHERE tenant_id = $1 AND key = 'llm_base_url'",
    )
    .bind(tenant_id)
    .fetch_optional(&mut *tx)
    .await
    .ok()??;
    let base = base_row
        .try_get::<String, _>("value")
        .ok()
        .filter(|s| !s.trim().is_empty())
        .unwrap_or_else(|| "http://127.0.0.1:8000/v1".into());
    let model =
        sqlx::query("SELECT value FROM system_configs WHERE tenant_id = $1 AND key = 'llm_model'")
            .bind(tenant_id)
            .fetch_optional(&mut *tx)
            .await
            .ok()
            .flatten()
            .and_then(|r| r.try_get::<String, _>("value").ok())
            .unwrap_or_default();
    let _ = tx.commit().await.ok()?;
    Some((base, model))
}

/// Merge edge assignment into async job payload (scan API). Loads LLM base URL / model from tenant `system_configs`.
pub async fn enrich_scan_payload_with_edge_node(
    pool: &sqlx::PgPool,
    tenant_id: i64,
    target: &str,
    payload: &mut Value,
) {
    let Some((llm_base_url, llm_model)) = load_llm_tenant_config(pool, tenant_id).await else {
        return;
    };
    let Some(fragment) = resolve_edge_swarm_for_target(
        pool.clone(),
        tenant_id,
        target,
        llm_base_url.as_str(),
        llm_model.as_str(),
        Some(tenant_id),
    )
    .await
    else {
        return;
    };
    let Some(obj) = payload.as_object_mut() else {
        return;
    };
    if let Value::Object(m) = fragment {
        for (k, v) in m {
            obj.insert(k, v);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn node(id: i64, region: &str, jobs: i32) -> EdgeNodeRow {
        EdgeNodeRow {
            id,
            region_code: region.to_string(),
            pop_label: "pop".to_string(),
            active_jobs: jobs,
            latitude: None,
            longitude: None,
        }
    }

    #[test]
    fn region_guess_eu() {
        assert_eq!(target_region_guess("eu-west-1.example.com"), Some("eu"));
        assert_eq!(target_region_guess("app.frankfurt.internal"), Some("eu"));
        assert_eq!(target_region_guess("https://shop.de/cart"), Some("eu"));
        assert_eq!(target_region_guess("host.ireland.corp"), Some("eu"));
    }

    #[test]
    fn region_guess_ap() {
        assert_eq!(target_region_guess("ap-southeast-2.aws"), Some("ap"));
        assert_eq!(target_region_guess("edge.tokyo.node"), Some("ap"));
        assert_eq!(target_region_guess("https://site.jp/index"), Some("ap"));
    }

    #[test]
    fn region_guess_us() {
        assert_eq!(target_region_guess("us-east-1.example.com"), Some("us"));
        assert_eq!(target_region_guess("db.virginia.local"), Some("us"));
        assert_eq!(target_region_guess("https://gov.us/portal"), Some("us"));
    }

    #[test]
    fn region_guess_is_case_insensitive() {
        assert_eq!(target_region_guess("EU-WEST-1.EXAMPLE.COM"), Some("eu"));
    }

    #[test]
    fn region_guess_none_for_unknown() {
        assert_eq!(target_region_guess("plain.example.org"), None);
        assert_eq!(target_region_guess("192.0.2.1"), None);
    }

    #[test]
    fn deterministic_pick_empty_is_none() {
        let nodes: Vec<EdgeNodeRow> = vec![];
        assert!(deterministic_pick(&nodes, "anything").is_none());
    }

    #[test]
    fn deterministic_pick_prefers_lowest_active_jobs() {
        let nodes = vec![node(1, "xx", 5), node(2, "yy", 2)];
        let picked = deterministic_pick(&nodes, "example.com").unwrap();
        assert_eq!(picked.id, 2);
    }

    #[test]
    fn deterministic_pick_region_hint_lowers_score() {
        // Same active_jobs; region match on the eu node subtracts 50 -> wins.
        let nodes = vec![node(1, "us-east", 3), node(2, "eu-central", 3)];
        let picked = deterministic_pick(&nodes, "eu-west-1.example.com").unwrap();
        assert_eq!(picked.id, 2);
    }

    #[test]
    fn deterministic_pick_ties_break_by_id() {
        let nodes = vec![node(5, "us", 0), node(3, "us", 0)];
        let picked = deterministic_pick(&nodes, "example.com").unwrap();
        assert_eq!(picked.id, 3);
    }

    #[test]
    fn parse_node_id_plain_object() {
        assert_eq!(parse_llm_node_id("{\"node_id\": 5}"), Some(5));
    }

    #[test]
    fn parse_node_id_with_surrounding_text() {
        assert_eq!(
            parse_llm_node_id("Here is my answer: {\"node_id\": 7} thanks"),
            Some(7)
        );
    }

    #[test]
    fn parse_node_id_chosen_node_id_alias() {
        assert_eq!(parse_llm_node_id("{\"chosen_node_id\": 9}"), Some(9));
    }

    #[test]
    fn parse_node_id_string_value_parsed() {
        assert_eq!(parse_llm_node_id("{\"node_id\": \"11\"}"), Some(11));
    }

    #[test]
    fn parse_node_id_no_braces_is_none() {
        assert_eq!(parse_llm_node_id("no json here"), None);
    }

    #[test]
    fn parse_node_id_invalid_json_is_none() {
        assert_eq!(parse_llm_node_id("{ not valid json }"), None);
    }

    #[test]
    fn parse_node_id_missing_key_is_none() {
        assert_eq!(parse_llm_node_id("{\"other\": 1}"), None);
    }
}
