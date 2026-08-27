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

/// Warm (or reuse) the in-memory index from cluster + finding targets.
pub async fn index_for_tenant(pool: &PgPool, tenant_id: i64) -> Arc<PathTemplateIndex> {
    if let Some(hit) = TENANT_INDEX.get(&tenant_id) {
        if hit.loaded_at.elapsed() < LEARN_TTL {
            return hit.index.clone();
        }
    }
    let index = Arc::new(PathTemplateIndex::new());
    if let Ok(mut tx) = crate::db::begin_tenant_tx(pool, tenant_id).await {
        if let Ok(rows) = sqlx::query_scalar::<_, String>(
            r#"SELECT target FROM weissman_finding_clusters
                WHERE tenant_id = $1 AND target <> ''
                ORDER BY last_seen_at DESC NULLS LAST
                LIMIT 2000"#,
        )
        .bind(tenant_id)
        .fetch_all(&mut *tx)
        .await
        {
            for t in rows {
                index.observe_url(&t);
            }
        }
        if let Ok(rows) = sqlx::query_scalar::<_, String>(
            r#"SELECT DISTINCT raw_data->>'target'
                 FROM vulnerabilities
                WHERE tenant_id = $1
                  AND raw_data->>'target' IS NOT NULL
                LIMIT 2000"#,
        )
        .bind(tenant_id)
        .fetch_all(&mut *tx)
        .await
        {
            for t in rows {
                index.observe_url(&t);
            }
        }
        let _ = tx.commit().await;
    }
    TENANT_INDEX.insert(
        tenant_id,
        CachedIndex {
            loaded_at: Instant::now(),
            index: index.clone(),
        },
    );
    index
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
}
