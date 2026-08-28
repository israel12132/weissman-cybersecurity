//! Tenant-scoped structural path templates.
//!
//! Local regex rules (UUID / hex / email / filename) catch canonical identifiers.
//! High-cardinality escapes — `alice`, `report_q3_final`, opaque slugs — are
//! learned by comparing other paths **in the same tenant**: a segment position
//! that already fans out to two or more non-reserved values is a variable and
//! becomes `{id}` for every later sibling.
//!
//! Prefix context is preserved, so `/api/v1/public/image/{id}` never collapses
//! onto `/api/v1/admin/billing/{id}`.

use dashmap::DashMap;
use sqlx::PgPool;
use std::collections::HashMap;
use std::sync::{Arc, LazyLock, RwLock};
use std::time::{Duration, Instant};

const LEARN_TTL: Duration = Duration::from_secs(60);
const MAX_PATHS_PER_TENANT: usize = 4000;
const MAX_CHILDREN: usize = 64;
/// Two distinct non-reserved siblings at the same prefix ⇒ that position is `{id}`.
const FANOUT_TO_VARIABLE: usize = 2;

static TENANT_INDEX: LazyLock<DashMap<i64, CachedIndex>> = LazyLock::new(DashMap::new);

struct CachedIndex {
    loaded_at: Instant,
    index: Arc<PathTemplateIndex>,
}

#[derive(Debug, Default)]
struct TrieNode {
    children: HashMap<String, TrieNode>,
    /// Non-reserved children at this node are interchangeable identifiers.
    wildcard: bool,
}

/// Learned route templates for one tenant.
#[derive(Debug, Default)]
pub struct PathTemplateIndex {
    root: RwLock<TrieNode>,
    observes: std::sync::atomic::AtomicUsize,
}

impl PathTemplateIndex {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Build an index from raw URLs (tests / batch observe).
    #[must_use]
    pub fn from_urls(urls: &[&str]) -> Self {
        let idx = Self::new();
        for u in urls {
            idx.observe_url(u);
        }
        idx
    }

    pub fn observe_url(&self, raw: &str) {
        let n = self.observes.load(std::sync::atomic::Ordering::Relaxed);
        if n >= MAX_PATHS_PER_TENANT {
            return;
        }
        let segs = path_segments(raw);
        if segs.is_empty() {
            return;
        }
        if let Ok(mut root) = self.root.write() {
            insert_path(&mut root, &segs);
            self.observes
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        }
    }

    /// Rewrite variable positions. Local structural rules apply first; tenant
    /// fan-out fills the gaps those rules miss.
    #[must_use]
    pub fn apply_segments(&self, segs: &[&str]) -> String {
        let last = segs.len().saturating_sub(1);
        let snap = self.root.read().ok();
        let mut node = snap.as_deref();
        let mut out = String::new();
        for (i, seg) in segs.iter().enumerate() {
            if i > 0 {
                out.push('/');
            }
            if seg.is_empty() {
                continue;
            }
            let local_var = crate::finding_identity::is_variable_path_segment(seg, i == last);
            let reserved = crate::finding_identity::is_reserved_route_token(seg);
            let learned = node.is_some_and(|n| n.wildcard) && !reserved;
            let hole = local_var || learned || *seg == "{id}";
            if hole && !reserved {
                out.push_str("{id}");
            } else {
                out.push_str(seg);
            }
            if let Some(n) = node {
                node = if hole {
                    n.children.get("{id}").or_else(|| n.children.get(*seg))
                } else {
                    n.children.get(*seg)
                };
            }
        }
        out
    }
}

fn insert_path(root: &mut TrieNode, segs: &[String]) {
    let last = segs.len().saturating_sub(1);
    {
        let mut node = &mut *root;
        for (i, seg) in segs.iter().enumerate() {
            let is_last = i == last;
            let key = if crate::finding_identity::is_variable_path_segment(seg, is_last)
                || seg == "{id}"
            {
                "{id}".to_string()
            } else {
                seg.clone()
            };
            if !node.children.contains_key(&key) && node.children.len() >= MAX_CHILDREN {
                node.wildcard = true;
                let _ = node.children.remove(seg);
                node.children.entry("{id}".to_string()).or_default();
                node = node.children.get_mut("{id}").expect("just inserted");
                continue;
            }
            node = node.children.entry(key).or_default();
        }
    }
    mark_wildcards(root);
}

fn mark_wildcards(node: &mut TrieNode) {
    let non_reserved = node
        .children
        .keys()
        .filter(|k| k.as_str() != "{id}" && !crate::finding_identity::is_reserved_route_token(k))
        .count();
    let has_hole = node.children.contains_key("{id}");
    if has_hole || non_reserved >= FANOUT_TO_VARIABLE {
        node.wildcard = true;
    }
    for child in node.children.values_mut() {
        mark_wildcards(child);
    }
}

/// Path segments of a URL or raw path, lower-cased, query/fragment stripped.
#[must_use]
pub fn path_segments(raw: &str) -> Vec<String> {
    let mut s = raw.trim().to_ascii_lowercase();
    if let Some(i) = s.find('#') {
        s.truncate(i);
    }
    if let Some(i) = s.find('?') {
        s.truncate(i);
    }
    let rest = if let Some(i) = s.find("://") {
        &s[i + 3..]
    } else {
        s.as_str()
    };
    let path = match rest.find('/') {
        Some(i) => &rest[i..],
        None => "",
    };
    path.split('/')
        .filter(|p| !p.is_empty())
        .map(|p| p.to_string())
        .collect()
}

const PERSISTED_TARGET_SQL: &str = r#"SELECT DISTINCT COALESCE(
                    NULLIF(raw_data->>'target', ''),
                    NULLIF(raw_data->>'target_url', ''),
                    NULLIF(raw_data->'raw'->>'url', ''),
                    NULLIF(raw_data->'raw'->>'target_url', ''),
                    NULLIF(raw_data->>'url', '')
                )
             FROM vulnerabilities
            WHERE tenant_id = $1
              AND COALESCE(
                    NULLIF(raw_data->>'target', ''),
                    NULLIF(raw_data->>'target_url', ''),
                    NULLIF(raw_data->'raw'->>'url', ''),
                    NULLIF(raw_data->'raw'->>'target_url', ''),
                    NULLIF(raw_data->>'url', '')
                  ) IS NOT NULL
            LIMIT 2000"#;

async fn observe_persisted_targets(
    pool: &PgPool,
    tenant_id: i64,
    index: &PathTemplateIndex,
) -> bool {
    let Ok(mut tx) = crate::db::begin_tenant_tx(pool, tenant_id).await else {
        return false;
    };
    let mut loaded_query = false;
    // Cluster targets are already route-normalized (`…/users/{id}`). Reloading
    // them after a reboot is what closes the cold-start hole: the next sibling
    // (`carol`) must not mint a new finding_id.
    match sqlx::query_scalar::<_, String>(
        r#"SELECT target FROM weissman_finding_clusters
            WHERE tenant_id = $1 AND target <> ''
            ORDER BY last_seen_at DESC NULLS LAST
            LIMIT 2000"#,
    )
    .bind(tenant_id)
    .fetch_all(&mut *tx)
    .await
    {
        Ok(rows) => {
            loaded_query = true;
            for t in rows {
                index.observe_url(&t);
            }
        }
        Err(e) => {
            tracing::warn!(
                target: "path_templates",
                tenant_id,
                error = %e,
                "cluster targets unavailable for trie pre-warm"
            );
        }
    }
    match sqlx::query_scalar::<_, String>(PERSISTED_TARGET_SQL)
        .bind(tenant_id)
        .fetch_all(&mut *tx)
        .await
    {
        Ok(rows) => {
            loaded_query = true;
            for t in rows {
                index.observe_url(&t);
            }
        }
        Err(e) => {
            tracing::warn!(
                target: "path_templates",
                tenant_id,
                error = %e,
                "vulnerability targets unavailable for trie pre-warm"
            );
        }
    }
    if !loaded_query {
        let _ = tx.rollback().await;
        return false;
    }
    tx.commit().await.is_ok()
}

/// Warm (or reuse) the in-memory index from cluster + finding targets.
pub async fn index_for_tenant(pool: &PgPool, tenant_id: i64) -> Arc<PathTemplateIndex> {
    if let Some(hit) = TENANT_INDEX.get(&tenant_id) {
        if hit.loaded_at.elapsed() < LEARN_TTL {
            return hit.index.clone();
        }
    }
    let index = Arc::new(PathTemplateIndex::new());
    let loaded = observe_persisted_targets(pool, tenant_id, index.as_ref()).await;
    // A failed tenant TX must not cache an empty trie for LEARN_TTL — that is
    // the cold-start leak (raw `/users/alice` hashed before siblings are known).
    if loaded {
        TENANT_INDEX.insert(
            tenant_id,
            CachedIndex {
                loaded_at: Instant::now(),
                index: index.clone(),
            },
        );
    }
    index
}

/// Load every active tenant's trie from persisted targets. Uses
/// [`weissman_db::active_tenant_ids`] (never a raw `tenants` scan).
pub async fn prewarm_all_tenants(pool: &PgPool) {
    let ids = match weissman_db::active_tenant_ids(pool).await {
        Ok(v) => v,
        Err(e) => {
            tracing::warn!(
                target: "path_templates",
                error = %e,
                "path-template pre-warm could not list tenants"
            );
            return;
        }
    };
    let n = ids.len();
    for tid in ids {
        let _ = index_for_tenant(pool, tid).await;
    }
    tracing::info!(
        target: "path_templates",
        tenants = n,
        "path-template trie pre-warmed from persisted cluster/finding targets"
    );
}

/// Boot hook: pre-warm in the background so the first persist after reboot does
/// not hash raw high-cardinality paths against an empty trie.
pub fn spawn_prewarm(pool: Arc<PgPool>) {
    tokio::spawn(async move {
        prewarm_all_tenants(pool.as_ref()).await;
    });
}

/// Drop the cached trie (tests / tenant delete).
pub fn invalidate_tenant(tenant_id: i64) {
    TENANT_INDEX.remove(&tenant_id);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::finding_identity::{build_cluster_key_ctx, normalize_target_ctx, IdentityHint};

    #[test]
    fn tenant_fanout_collapses_usernames_keeps_public_vs_admin() {
        let idx = PathTemplateIndex::from_urls(&[
            "https://api.corp/api/v1/users/alice",
            "https://api.corp/api/v1/users/bob",
            "https://api.corp/api/v1/public/image/foo@corp.com",
            "https://api.corp/api/v1/admin/billing/invoice_august_2026.pdf",
        ]);
        let hint = IdentityHint::default();
        let alice = normalize_target_ctx("https://api.corp/api/v1/users/carol", &hint, Some(&idx));
        assert_eq!(alice, "https://api.corp/api/v1/users/{id}");
        let public = normalize_target_ctx(
            "https://api.corp/api/v1/public/image/foo@corp.com",
            &hint,
            Some(&idx),
        );
        let admin = normalize_target_ctx(
            "https://api.corp/api/v1/admin/billing/invoice_august_2026.pdf",
            &hint,
            Some(&idx),
        );
        assert_eq!(public, "https://api.corp/api/v1/public/image/{id}");
        assert_eq!(admin, "https://api.corp/api/v1/admin/billing/{id}");
        assert_ne!(
            build_cluster_key_ctx(&public, "xss", "CWE-79", &hint, Some(&idx)),
            build_cluster_key_ctx(&admin, "xss", "CWE-79", &hint, Some(&idx))
        );
    }

    #[test]
    fn single_unseen_name_does_not_invent_a_hole() {
        let idx = PathTemplateIndex::from_urls(&["https://api.corp/api/v1/users/alice"]);
        let n = normalize_target_ctx(
            "https://api.corp/api/v1/users/alice",
            &IdentityHint::default(),
            Some(&idx),
        );
        assert_eq!(n, "https://api.corp/api/v1/users/alice");
    }

    #[test]
    fn reboot_from_persisted_id_template_still_collapses_next_sibling() {
        // After a cold start the trie is rebuilt from cluster.target rows, which
        // persist already-normalized (`…/users/{id}`). Carol must not mint a
        // new finding_id just because the process forgot alice/bob.
        let reloaded = PathTemplateIndex::from_urls(&["https://api.corp/api/v1/users/{id}"]);
        let carol = normalize_target_ctx(
            "https://api.corp/api/v1/users/carol",
            &IdentityHint::default(),
            Some(&reloaded),
        );
        assert_eq!(carol, "https://api.corp/api/v1/users/{id}");
        let public = normalize_target_ctx(
            "https://api.corp/api/v1/public/image/new@corp.com",
            &IdentityHint::default(),
            Some(&reloaded),
        );
        assert_eq!(public, "https://api.corp/api/v1/public/image/{id}");
    }

    #[test]
    fn boot_hooks_prewarm_the_trie_on_server_and_worker() {
        let serve = include_str!("http/serve.rs");
        assert!(
            serve.contains("path_templates::spawn_prewarm"),
            "Axum boot must pre-warm the per-tenant trie"
        );
        let worker = include_str!("../../crates/weissman-worker/src/main.rs");
        assert!(
            worker.contains("path_templates::spawn_prewarm"),
            "worker boot must pre-warm the per-tenant trie"
        );
    }
}
