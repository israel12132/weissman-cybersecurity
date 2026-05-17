//! CNAPP Layer 1: Contextual risk graph — omni-source assets, delta upserts (no destructive rebuild),
//! blast-radius scoring, and D3/WebGL export for AI + cockpit visualisation.

use chrono::Utc;
use serde_json::{json, Value};
use sqlx::{Postgres, Row, Transaction};
use std::collections::{HashMap, HashSet, VecDeque};

/// Node types in the risk graph (derived from live data).
pub const NODE_ASSET: &str = "asset";
pub const NODE_IDENTITY: &str = "identity";
pub const NODE_NETWORK: &str = "network";
pub const NODE_FINDING: &str = "finding";
pub const NODE_PACKAGE: &str = "package";
pub const NODE_REPO: &str = "repo";
pub const NODE_PHYSICAL_ASSET: &str = "physical_asset";
/// AWS / GCP / Azure style resource (inventory-backed).
pub const NODE_CLOUD_RESOURCE: &str = "cloud_resource";
/// Kubernetes cluster (or aggregated control-plane scope).
pub const NODE_K8S_CLUSTER: &str = "k8s_cluster";

/// Edge types.
pub const EDGE_EXPOSES: &str = "exposes";
pub const EDGE_AUTHENTICATES: &str = "authenticates";
pub const EDGE_AFFECTS: &str = "affects";
pub const EDGE_CONNECTS: &str = "connects";
pub const EDGE_LEADS_TO: &str = "leads_to";
/// Cloud IAM / trust boundary (identity or role → resource).
pub const EDGE_HAS_PERMISSION: &str = "has_permission";

fn physical_asset_class(protocol: &str) -> &'static str {
    match protocol {
        "modbus_tcp" => "PLC / field device (Modbus)",
        "ethernet_ip_cip" => "Industrial controller (EtherNet/IP)",
        "s7_iso_tcp" => "PLC (S7 / ISO-on-TCP)",
        _ => "Physical / OT asset",
    }
}

/// Upsert a node by stable `(tenant_id, client_id, graph_key)`; returns DB `id`.
async fn risk_ensure_node(
    tx: &mut Transaction<'_, Postgres>,
    tenant_id: i64,
    client_id: i64,
    node_type: &str,
    label: &str,
    external_id: Option<&str>,
    graph_key: &str,
    node_id_by_key: &mut HashMap<String, i64>,
) -> Result<i64, sqlx::Error> {
    if let Some(&id) = node_id_by_key.get(graph_key) {
        return Ok(id);
    }
    let ext = external_id.unwrap_or("");
    let id: i64 = sqlx::query_scalar(
        r#"INSERT INTO risk_graph_nodes (
                tenant_id, client_id, node_type, label, external_id, metadata, graph_key, risk_score, is_choke_point
            ) VALUES ($1, $2, $3, $4, NULLIF($5, ''), '{}', $6, 0, false)
            ON CONFLICT (tenant_id, client_id, graph_key) DO UPDATE SET
                node_type = EXCLUDED.node_type,
                label = EXCLUDED.label,
                external_id = EXCLUDED.external_id,
                metadata = EXCLUDED.metadata
            RETURNING id"#,
    )
    .bind(tenant_id)
    .bind(client_id)
    .bind(node_type)
    .bind(label)
    .bind(ext)
    .bind(graph_key)
    .fetch_one(&mut **tx)
    .await?;
    node_id_by_key.insert(graph_key.to_string(), id);
    Ok(id)
}

async fn risk_upsert_edge(
    tx: &mut Transaction<'_, Postgres>,
    tenant_id: i64,
    client_id: i64,
    from_node_id: i64,
    to_node_id: i64,
    edge_type: &str,
) -> Result<(), sqlx::Error> {
    sqlx::query(
        r#"INSERT INTO risk_graph_edges (tenant_id, client_id, from_node_id, to_node_id, edge_type, metadata)
           VALUES ($1, $2, $3, $4, $5, '{}')
           ON CONFLICT (tenant_id, client_id, from_node_id, to_node_id, edge_type) DO NOTHING"#,
    )
    .bind(tenant_id)
    .bind(client_id)
    .bind(from_node_id)
    .bind(to_node_id)
    .bind(edge_type)
    .execute(&mut **tx)
    .await?;
    Ok(())
}

fn base_risk_score(node_type: &str) -> i32 {
    match node_type {
        NODE_FINDING => 92,
        NODE_CLOUD_RESOURCE => 58,
        NODE_K8S_CLUSTER => 56,
        NODE_PHYSICAL_ASSET => 48,
        NODE_ASSET => 42,
        NODE_IDENTITY => 38,
        NODE_NETWORK => 34,
        NODE_PACKAGE | NODE_REPO => 28,
        _ => 35,
    }
}

/// Recompute `risk_score` and `is_choke_point` from incident edges (blast / centrality proxy).
async fn recompute_risk_scores_and_chokes(
    tx: &mut Transaction<'_, Postgres>,
    tenant_id: i64,
    client_id: i64,
) -> Result<(), sqlx::Error> {
    let nodes: Vec<(i64, String)> = sqlx::query_as(
        "SELECT id, node_type FROM risk_graph_nodes WHERE tenant_id = $1 AND client_id = $2",
    )
    .bind(tenant_id)
    .bind(client_id)
    .fetch_all(&mut **tx)
    .await?;

    let edges: Vec<(i64, i64, String)> = sqlx::query_as(
        "SELECT from_node_id, to_node_id, edge_type FROM risk_graph_edges WHERE tenant_id = $1 AND client_id = $2",
    )
    .bind(tenant_id)
    .bind(client_id)
    .fetch_all(&mut **tx)
    .await?;

    let mut deg: HashMap<i64, usize> = HashMap::new();
    let mut types: HashMap<i64, HashSet<String>> = HashMap::new();
    for (from, to, et) in &edges {
        *deg.entry(*from).or_default() += 1;
        *deg.entry(*to).or_default() += 1;
        types.entry(*from).or_default().insert(et.clone());
        types.entry(*to).or_default().insert(et.clone());
    }

    let mut sorted_deg: Vec<usize> = deg.values().copied().collect();
    sorted_deg.sort_unstable();
    let p75 = sorted_deg
        .get((sorted_deg.len().saturating_mul(3)) / 4)
        .copied()
        .unwrap_or(0)
        .max(3);

    for (nid, nt) in &nodes {
        let mut score = base_risk_score(nt.as_str());
        let ts = types.get(nid).cloned().unwrap_or_default();

        if nt.as_str() == NODE_ASSET {
            let has_exp = ts.contains(EDGE_EXPOSES);
            let has_auth = ts.contains(EDGE_AUTHENTICATES);
            let has_conn = ts.contains(EDGE_CONNECTS);
            let mult = if has_exp && has_auth && has_conn {
                2.85
            } else if has_exp && (has_auth || has_conn) {
                1.9
            } else if has_exp {
                1.45
            } else {
                1.0
            };
            score = ((score as f64) * mult).round() as i32;
        } else if nt.as_str() == NODE_FINDING && ts.len() >= 2 {
            score = ((score as f64) * 1.08).round() as i32;
        }

        score = score.clamp(0, 100);
        let d = deg.get(nid).copied().unwrap_or(0);
        let choke = d >= p75 && ts.len() >= 2;

        sqlx::query(
            "UPDATE risk_graph_nodes SET risk_score = $1, is_choke_point = $2 \
             WHERE id = $3 AND tenant_id = $4 AND client_id = $5",
        )
        .bind(score)
        .bind(choke)
        .bind(nid)
        .bind(tenant_id)
        .bind(client_id)
        .execute(&mut **tx)
        .await?;
    }

    Ok(())
}

/// Build or **merge** the risk graph for a client from live DB (delta upserts; no table-wide DELETE).
pub async fn build_risk_graph_for_client(
    tx: &mut Transaction<'_, Postgres>,
    tenant_id: i64,
    client_id: i64,
) -> Result<(usize, usize), sqlx::Error> {
    let mut node_id_by_key: HashMap<String, i64> = HashMap::new();

    let vulns: Vec<(i64, String, String, String)> = sqlx::query_as(
        "SELECT id, finding_id, title, source FROM vulnerabilities WHERE client_id = $1 AND status = 'OPEN'",
    )
    .bind(client_id)
    .fetch_all(&mut **tx)
    .await?;

    for (_vid, fid, title, source) in &vulns {
        let key = format!("finding:{fid}");
        let nid = risk_ensure_node(
            tx,
            tenant_id,
            client_id,
            NODE_FINDING,
            &format!(
                "{} [{}]",
                title.chars().take(40).collect::<String>(),
                source
            ),
            Some(fid.as_str()),
            &key,
            &mut node_id_by_key,
        )
        .await?;
        let asset_key = format!("asset:client:{client_id}");
        let aid = risk_ensure_node(
            tx,
            tenant_id,
            client_id,
            NODE_ASSET,
            "Target Asset",
            Some(&client_id.to_string()),
            &asset_key,
            &mut node_id_by_key,
        )
        .await?;
        risk_upsert_edge(
            tx,
            tenant_id,
            client_id,
            aid,
            nid,
            EDGE_EXPOSES,
        )
        .await?;
    }

    let identities: Vec<(String, i32)> = sqlx::query_as(
        "SELECT role_name, privilege_order FROM identity_contexts WHERE client_id = $1",
    )
    .bind(client_id)
    .fetch_all(&mut **tx)
    .await?;

    let asset_key = format!("asset:client:{client_id}");
    let aid = risk_ensure_node(
        tx,
        tenant_id,
        client_id,
        NODE_ASSET,
        "Target Asset",
        Some(&client_id.to_string()),
        &asset_key,
        &mut node_id_by_key,
    )
    .await?;

    for (role, _order) in &identities {
        let key = format!("identity:{role}");
        let iid = risk_ensure_node(
            tx,
            tenant_id,
            client_id,
            NODE_IDENTITY,
            role,
            Some(role.as_str()),
            &key,
            &mut node_id_by_key,
        )
        .await?;
        risk_upsert_edge(
            tx,
            tenant_id,
            client_id,
            iid,
            aid,
            EDGE_AUTHENTICATES,
        )
        .await?;
    }

    let asm_nodes: Vec<(String, String, String)> = sqlx::query_as(
        "SELECT node_id, label, node_type FROM asm_graph_nodes WHERE client_id = $1 LIMIT 100",
    )
    .bind(client_id)
    .fetch_all(&mut **tx)
    .await?;

    for (nid_asm, label, _ntype) in &asm_nodes {
        let key = format!("network:{nid_asm}");
        let net_id = risk_ensure_node(
            tx,
            tenant_id,
            client_id,
            NODE_NETWORK,
            label,
            Some(nid_asm.as_str()),
            &key,
            &mut node_id_by_key,
        )
        .await?;
        risk_upsert_edge(
            tx,
            tenant_id,
            client_id,
            net_id,
            aid,
            EDGE_CONNECTS,
        )
        .await?;
    }

    let ot_rows: Vec<(i64, String, i32, String, String)> = sqlx::query_as(
        "SELECT id, host, port, protocol, vendor_hint FROM ot_ics_fingerprints WHERE client_id = $1 ORDER BY id",
    )
    .bind(client_id)
    .fetch_all(&mut **tx)
    .await
    .unwrap_or_default();

    for (ot_id, host, port, protocol, vendor_hint) in &ot_rows {
        let physical_class = physical_asset_class(protocol);
        let label = format!(
            "{} {}:{} — {}",
            physical_class,
            host,
            port,
            vendor_hint.chars().take(36).collect::<String>()
        );
        let ext = format!("ot:{host}:{port}:{protocol}");
        let key = format!("physical:{ot_id}");
        let pid = risk_ensure_node(
            tx,
            tenant_id,
            client_id,
            NODE_PHYSICAL_ASSET,
            &label,
            Some(ext.as_str()),
            &key,
            &mut node_id_by_key,
        )
        .await?;
        risk_upsert_edge(
            tx,
            tenant_id,
            client_id,
            pid,
            aid,
            EDGE_AFFECTS,
        )
        .await?;
    }

    // --- Omni-source: AWS (inventory table; empty until cloud sync populates rows) ---
    let aws_rows: Vec<(i64, String, Option<String>, Option<String>, Option<String>)> =
        sqlx::query_as(
            r#"SELECT id, asset_arn, region, service_name, resource_type
               FROM aws_assets WHERE tenant_id = $1 AND client_id = $2 LIMIT 500"#,
        )
        .bind(tenant_id)
        .bind(client_id)
        .fetch_all(&mut **tx)
        .await
        .unwrap_or_default();

    for (_aws_id, arn, region, service, rtype) in &aws_rows {
        let r = region.clone().unwrap_or_default();
        let svc = service.clone().unwrap_or_default();
        let rt = rtype.clone().unwrap_or_default();
        let label = format!("AWS {rt} — {svc} ({r})");
        let gkey = format!("aws:{arn}");
        let cid = risk_ensure_node(
            tx,
            tenant_id,
            client_id,
            NODE_CLOUD_RESOURCE,
            &label.chars().take(200).collect::<String>(),
            Some(arn.as_str()),
            &gkey,
            &mut node_id_by_key,
        )
        .await?;
        risk_upsert_edge(
            tx,
            tenant_id,
            client_id,
            aid,
            cid,
            EDGE_CONNECTS,
        )
        .await?;
    }

    // --- Omni-source: Kubernetes ---
    let k8s_rows: Vec<(i64, String, Option<String>, String, String, String)> = sqlx::query_as(
        r#"SELECT id, cluster_uid, cluster_name, namespace, kind, name
           FROM k8s_assets WHERE tenant_id = $1 AND client_id = $2 LIMIT 500"#,
    )
    .bind(tenant_id)
    .bind(client_id)
    .fetch_all(&mut **tx)
    .await
    .unwrap_or_default();

    for (_kid, uid, cname, ns, kind, name) in &k8s_rows {
        let cn = cname.clone().unwrap_or_else(|| "cluster".into());
        let label = if name.is_empty() {
            format!("K8s {kind} — {cn}")
        } else {
            format!("K8s {kind}/{name} — {cn} [{ns}]")
        };
        let gkey = format!("k8s:{uid}:{ns}:{kind}:{name}");
        let kid = risk_ensure_node(
            tx,
            tenant_id,
            client_id,
            NODE_K8S_CLUSTER,
            &label.chars().take(200).collect::<String>(),
            Some(uid.as_str()),
            &gkey,
            &mut node_id_by_key,
        )
        .await?;
        risk_upsert_edge(
            tx,
            tenant_id,
            client_id,
            aid,
            kid,
            EDGE_CONNECTS,
        )
        .await?;
    }

    // IAM-style permission stubs: cap to avoid quadratic blow-up on large tenants.
    let cloud_ids: Vec<i64> = node_id_by_key
        .iter()
        .filter(|(k, _)| k.starts_with("aws:"))
        .map(|(_, &v)| v)
        .take(12)
        .collect();
    let identity_ids: Vec<i64> = node_id_by_key
        .iter()
        .filter(|(k, _)| k.starts_with("identity:"))
        .map(|(_, &v)| v)
        .take(10)
        .collect();
    for iid in &identity_ids {
        for cid in &cloud_ids {
            risk_upsert_edge(
                tx,
                tenant_id,
                client_id,
                *iid,
                *cid,
                EDGE_HAS_PERMISSION,
            )
            .await?;
        }
    }

    recompute_risk_scores_and_chokes(tx, tenant_id, client_id).await?;

    let node_count: i64 = sqlx::query_scalar(
        "SELECT COUNT(*)::bigint FROM risk_graph_nodes WHERE tenant_id = $1 AND client_id = $2",
    )
    .bind(tenant_id)
    .bind(client_id)
    .fetch_one(&mut **tx)
    .await
    .unwrap_or(0);
    let edge_count: i64 = sqlx::query_scalar(
        "SELECT COUNT(*)::bigint FROM risk_graph_edges WHERE tenant_id = $1 AND client_id = $2",
    )
    .bind(tenant_id)
    .bind(client_id)
    .fetch_one(&mut **tx)
    .await
    .unwrap_or(0);
    Ok((node_count as usize, edge_count as usize))
}

/// vLLM-assisted links from OT physical assets (`physical:{ot_row_id}`) to ASM network nodes (`network:{asm_node_id}`).
/// Run **after** [`build_risk_graph_for_client`] so graph_keys exist. Returns number of new edges inserted.
pub async fn fusion_ot_it_graph_edges_llm(
    pool: &sqlx::PgPool,
    tenant_id: i64,
    client_id: i64,
    llm_base_url: &str,
    llm_model: &str,
) -> Result<usize, sqlx::Error> {
    let mut tx = crate::db::begin_tenant_tx(pool, tenant_id).await?;
    let ot_rows: Vec<(i64, String, i32, String, String)> = sqlx::query_as(
        "SELECT id, host, port, protocol, vendor_hint FROM ot_ics_fingerprints WHERE client_id = $1 ORDER BY id LIMIT 80",
    )
    .bind(client_id)
    .fetch_all(&mut *tx)
    .await?;
    let asm_rows: Vec<(String, String, String)> = sqlx::query_as(
        "SELECT node_id, label, node_type FROM asm_graph_nodes WHERE client_id = $1 LIMIT 120",
    )
    .bind(client_id)
    .fetch_all(&mut *tx)
    .await?;
    let _ = tx.commit().await?;

    if ot_rows.is_empty() || asm_rows.is_empty() || llm_base_url.trim().is_empty() {
        return Ok(0);
    }

    let ot_json: Value = Value::Array(
        ot_rows
            .iter()
            .map(|(id, host, port, proto, vendor)| {
                json!({
                    "ot_row_id": id,
                    "host": host,
                    "port": port,
                    "protocol": proto,
                    "vendor_hint": vendor,
                })
            })
            .collect(),
    );
    let asm_json: Value = Value::Array(
        asm_rows
            .iter()
            .map(|(nid, label, ntype)| {
                json!({
                    "asm_node_id": nid,
                    "label": label,
                    "node_type": ntype,
                })
            })
            .collect(),
    );
    let user = format!(
        "Map OT/ICS field devices to IT attack-surface (ASM) hosts that likely share a network path or hostname correlation.\n\
         OT devices:\n{}\n\nASM nodes:\n{}\n\n\
         Output ONLY JSON: {{\"links\":[{{\"ot_row_id\": <int>, \"asm_node_id\": \"<string from asm_node_id>\", \"rationale\": \"brief\"}}]}}\n\
         Include only high-confidence correlations (shared IP segment, hostname token, or obvious plant network). Max 24 links.",
        serde_json::to_string_pretty(&ot_json).unwrap_or_else(|_| "[]".into()),
        serde_json::to_string_pretty(&asm_json).unwrap_or_else(|_| "[]".into())
    );
    let client = weissman_engines::openai_chat::llm_http_client(90);
    let model = weissman_engines::openai_chat::resolve_llm_model(llm_model);
    let text = match weissman_engines::openai_chat::chat_completion_text(
        &client,
        llm_base_url,
        model.as_str(),
        Some("You fuse OT discovery with IT ASM graphs for authorized security assessments. Output only JSON as specified."),
        &user,
        0.12,
        2048,
        Some(tenant_id),
        "risk_graph_ot_it_fusion",
        false,
    )
    .await
    {
        Ok(t) => t,
        Err(_) => return Ok(0),
    };

    let links = parse_ot_it_fusion_response(&text);
    if links.is_empty() {
        return Ok(0);
    }

    let mut tx = crate::db::begin_tenant_tx(pool, tenant_id).await?;
    let mut inserted = 0usize;
    for (ot_id, asm_nid) in links {
        let from_key = format!("physical:{ot_id}");
        let to_key = format!("network:{asm_nid}");
        let from_id: Option<i64> = sqlx::query_scalar(
            "SELECT id FROM risk_graph_nodes WHERE tenant_id = $1 AND client_id = $2 AND graph_key = $3",
        )
        .bind(tenant_id)
        .bind(client_id)
        .bind(&from_key)
        .fetch_optional(&mut *tx)
        .await?;
        let to_id: Option<i64> = sqlx::query_scalar(
            "SELECT id FROM risk_graph_nodes WHERE tenant_id = $1 AND client_id = $2 AND graph_key = $3",
        )
        .bind(tenant_id)
        .bind(client_id)
        .bind(&to_key)
        .fetch_optional(&mut *tx)
        .await?;
        if let (Some(f), Some(t)) = (from_id, to_id) {
            risk_upsert_edge(&mut tx, tenant_id, client_id, f, t, EDGE_CONNECTS).await?;
            inserted += 1;
        }
    }
    if inserted > 0 {
        recompute_risk_scores_and_chokes(&mut tx, tenant_id, client_id).await?;
    }
    tx.commit().await?;
    Ok(inserted)
}

fn parse_ot_it_fusion_response(text: &str) -> Vec<(i64, String)> {
    let t = text.trim();
    let start = t.find('{').unwrap_or(0);
    let end = t.rfind('}').map(|i| i + 1).unwrap_or(t.len());
    let slice = t.get(start..end).unwrap_or("");
    let Ok(v) = serde_json::from_str::<Value>(slice) else {
        return Vec::new();
    };
    let Some(arr) = v.get("links").and_then(Value::as_array) else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for item in arr.iter().take(32) {
        let Some(oid) = item.get("ot_row_id").and_then(|x| x.as_i64()) else {
            continue;
        };
        let Some(asm) = item
            .get("asm_node_id")
            .and_then(|x| x.as_str())
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
        else {
            continue;
        };
        out.push((oid, asm));
    }
    out
}

fn undirected_adj(edges: &[(i64, i64, String)]) -> HashMap<i64, Vec<(i64, String)>> {
    let mut m: HashMap<i64, Vec<(i64, String)>> = HashMap::new();
    for (a, b, et) in edges {
        m.entry(*a).or_default().push((*b, et.clone()));
        m.entry(*b).or_default().push((*a, et.clone()));
    }
    m
}

/// Shortest blast paths (undirected) from high-value sources to crown-jewel targets.
fn collect_blast_paths(
    adj: &HashMap<i64, Vec<(i64, String)>>,
    sources: &[i64],
    targets: &HashSet<i64>,
    max_depth: usize,
    max_paths: usize,
) -> Vec<Value> {
    let mut out = Vec::new();
    'sources: for &start in sources {
        if out.len() >= max_paths {
            break;
        }
        let mut q = VecDeque::new();
        let mut visited = HashSet::new();
        q.push_back((start, vec![start], Vec::<String>::new()));
        visited.insert(start);
        while let Some((cur, path, ets)) = q.pop_front() {
            if path.len() > max_depth {
                continue;
            }
            if cur != start && targets.contains(&cur) {
                out.push(json!({
                    "severity": "critical",
                    "source_id": start,
                    "sink_id": cur,
                    "hop_count": path.len().saturating_sub(1),
                    "node_ids": path,
                    "edge_types": ets,
                    "rationale": "undirected connectivity: finding / exposure blast toward crown-jewel asset or control plane"
                }));
                if out.len() >= max_paths {
                    break 'sources;
                }
                continue;
            }
            if path.len() >= max_depth {
                continue;
            }
            for (nb, et) in adj.get(&cur).into_iter().flatten() {
                if path.contains(nb) {
                    continue;
                }
                let mut p2 = path.clone();
                p2.push(*nb);
                let mut e2 = ets.clone();
                e2.push(et.clone());
                if visited.insert(*nb) {
                    q.push_back((*nb, p2, e2));
                }
            }
        }
    }
    out
}

fn build_nested_hierarchy(
    root: i64,
    adj: &HashMap<i64, Vec<(i64, String)>>,
    id_to_meta: &HashMap<i64, (String, String, i32, bool)>,
    seen: &mut HashSet<i64>,
    depth: usize,
    max_depth: usize,
) -> Value {
    if depth > max_depth {
        return json!({});
    }
    let (nt, label, rs, choke) = id_to_meta
        .get(&root)
        .cloned()
        .unwrap_or_else(|| ("unknown".into(), format!("node {root}"), 0, false));
    let mut children = Vec::new();
    if let Some(nbrs) = adj.get(&root) {
        for (nb, et) in nbrs {
            if !seen.insert(*nb) {
                continue;
            }
            let mut ch = build_nested_hierarchy(*nb, adj, id_to_meta, seen, depth + 1, max_depth);
            if let Some(obj) = ch.as_object_mut() {
                obj.insert("link_edge_type".into(), json!(et));
            }
            children.push(ch);
        }
    }
    json!({
        "id": root,
        "node_type": nt,
        "label": label,
        "risk_score": rs,
        "is_choke_point": choke,
        "visual": { "radius": rs.max(8).min(64), "glow": choke },
        "children": children
    })
}

fn meta_json_str(s: &str) -> Value {
    serde_json::from_str::<Value>(s).unwrap_or_else(|_| json!({ "raw": s }))
}

/// Export nested graph JSON for D3.js / WebGL / vLLM consumption (includes blast-radius paths).
pub async fn export_risk_graph_json(
    pool: &sqlx::PgPool,
    tenant_id: i64,
    client_id: i64,
) -> Result<Value, sqlx::Error> {
    let mut tx = crate::db::begin_tenant_tx(pool, tenant_id).await?;

    let node_rows = sqlx::query(
        r#"SELECT id, graph_key, node_type, label, external_id, metadata, risk_score, is_choke_point
           FROM risk_graph_nodes WHERE tenant_id = $1 AND client_id = $2 ORDER BY id"#,
    )
    .bind(tenant_id)
    .bind(client_id)
    .fetch_all(&mut *tx)
    .await?;

    let edge_rows = sqlx::query(
        r#"SELECT id, from_node_id, to_node_id, edge_type, metadata
           FROM risk_graph_edges WHERE tenant_id = $1 AND client_id = $2 ORDER BY id"#,
    )
    .bind(tenant_id)
    .bind(client_id)
    .fetch_all(&mut *tx)
    .await?;

    tx.commit().await?;

    let mut id_to_meta: HashMap<i64, (String, String, i32, bool)> = HashMap::new();
    let mut nodes_flat: Vec<Value> = Vec::new();
    let mut finding_ids = Vec::new();
    let mut jewel_ids: HashSet<i64> = HashSet::new();

    for r in &node_rows {
        let id: i64 = r.try_get("id").unwrap_or(0);
        let gk: String = r.try_get("graph_key").unwrap_or_default();
        let nt: String = r.try_get("node_type").unwrap_or_default();
        let label: String = r.try_get("label").unwrap_or_default();
        let ext: Option<String> = r.try_get("external_id").ok().flatten();
        let meta_s: String = r.try_get("metadata").unwrap_or_else(|_| "{}".into());
        let rs: i32 = r.try_get("risk_score").unwrap_or(0);
        let choke: bool = r.try_get("is_choke_point").unwrap_or(false);

        id_to_meta.insert(id, (nt.clone(), label.clone(), rs, choke));

        if nt == NODE_FINDING {
            finding_ids.push(id);
        }
        if nt == NODE_ASSET
            || nt == NODE_CLOUD_RESOURCE
            || nt == NODE_K8S_CLUSTER
            || nt == NODE_PHYSICAL_ASSET
        {
            jewel_ids.insert(id);
        }

        nodes_flat.push(json!({
            "id": id,
            "graph_key": gk,
            "node_type": nt,
            "label": label,
            "external_id": ext,
            "metadata": meta_json_str(&meta_s),
            "risk_score": rs,
            "is_choke_point": choke,
        }));
    }

    let mut edges_struct: Vec<Value> = Vec::new();
    let mut edge_tuples: Vec<(i64, i64, String)> = Vec::new();
    for r in &edge_rows {
        let id: i64 = r.try_get("id").unwrap_or(0);
        let from: i64 = r.try_get("from_node_id").unwrap_or(0);
        let to: i64 = r.try_get("to_node_id").unwrap_or(0);
        let et: String = r.try_get("edge_type").unwrap_or_default();
        let meta_s: String = r.try_get("metadata").unwrap_or_else(|_| "{}".into());
        edges_struct.push(json!({
            "id": id,
            "source": from,
            "target": to,
            "edge_type": et,
            "metadata": meta_json_str(&meta_s),
            "directed": true
        }));
        edge_tuples.push((from, to, et));
    }

    let adj = undirected_adj(&edge_tuples);
    let blast_paths = collect_blast_paths(&adj, &finding_ids, &jewel_ids, 10, 64);

    let asset_root_key = format!("asset:client:{client_id}");
    let root_id = node_rows
        .iter()
        .find(|r| r.try_get::<String, _>("graph_key").ok().as_deref() == Some(&asset_root_key))
        .and_then(|r| r.try_get::<i64, _>("id").ok());

    let mut hierarchy = json!({});
    if let Some(rid) = root_id {
        let mut seen = HashSet::new();
        seen.insert(rid);
        hierarchy = build_nested_hierarchy(rid, &adj, &id_to_meta, &mut seen, 0, 6);
    }

    let hubs: Vec<Value> = node_rows
        .iter()
        .filter_map(|r| {
            let choke: bool = r.try_get("is_choke_point").unwrap_or(false);
            if !choke {
                return None;
            }
            Some(json!({
                "id": r.try_get::<i64,_>("id").unwrap_or(0),
                "label": r.try_get::<String,_>("label").unwrap_or_default(),
                "node_type": r.try_get::<String,_>("node_type").unwrap_or_default(),
                "risk_score": r.try_get::<i32,_>("risk_score").unwrap_or(0),
            }))
        })
        .collect();

    Ok(json!({
        "meta": {
            "tenant_id": tenant_id,
            "client_id": client_id,
            "exported_at": Utc::now().to_rfc3339(),
            "format": "weissman_risk_graph_omni_v1",
            "stats": {
                "node_count": nodes_flat.len(),
                "edge_count": edges_struct.len(),
                "finding_count": finding_ids.len(),
                "blast_path_count": blast_paths.len()
            }
        },
        "graph": {
            "nodes": nodes_flat,
            "links": edges_struct
        },
        "layout3d": {
            "hierarchy_root_id": root_id,
            "nested": hierarchy
        },
        "blast_radius": {
            "paths": blast_paths,
            "choke_point_hubs": hubs,
            "notes": "Paths are undirected shortest walks from OPEN finding nodes toward crown-jewel classes (asset, cloud, k8s, OT)."
        }
    }))
}
