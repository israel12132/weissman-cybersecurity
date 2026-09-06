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
//!
//! The trie snapshot is `ArcSwap<TrieNode>`: persist **reads** a frozen `Arc`
//! and never waits on writers. **Writes** take a short `Mutex` (single-writer)
//! then `store` the new snapshot — no CAS retry spin under a scan burst.

use arc_swap::ArcSwap;
use dashmap::DashMap;
use futures::stream::{self, StreamExt};
use sqlx::PgPool;
use std::collections::HashMap;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, LazyLock, Mutex};
use std::time::{Duration, Instant};

const LEARN_TTL: Duration = Duration::from_secs(60);
const MAX_PATHS_PER_TENANT: usize = 25_000;
const MAX_CHILDREN: usize = 64;
/// Two distinct non-reserved siblings at the same prefix ⇒ that position is `{id}`.
const FANOUT_TO_VARIABLE: usize = 2;
/// Unique-path pages for cold-start pre-warm (never a full-table jsonb dump).
const PREWARM_BATCH: i64 = 25_000;
const PREWARM_WINDOW_SQL: &str = "90 days";
/// Boot fan-out: enough to cut sequential startup, small enough that 10
/// tenant DISTINCT pages cannot starve the pool or trip a liveness probe.
const PREWARM_CONCURRENCY: usize = 10;

static TENANT_INDEX: LazyLock<DashMap<i64, CachedIndex>> = LazyLock::new(DashMap::new);

struct CachedIndex {
    loaded_at: Instant,
    index: Arc<PathTemplateIndex>,
}

#[derive(Clone, Debug, Default)]
struct TrieNode {
    children: HashMap<String, TrieNode>,
    /// Non-reserved children at this node are interchangeable identifiers.
    wildcard: bool,
}

/// Learned route templates for one tenant.
pub struct PathTemplateIndex {
    root: ArcSwap<TrieNode>,
    observes: AtomicUsize,
    /// Serializes writers so a scan burst cannot spin `rcu` to 100% CPU.
    /// Readers (`apply_segments`) still `load()` a frozen snapshot with no lock.
    write: Mutex<()>,
}

impl Default for PathTemplateIndex {
    fn default() -> Self {
        Self {
            root: ArcSwap::from_pointee(TrieNode::default()),
            observes: AtomicUsize::new(0),
            write: Mutex::new(()),
        }
    }
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
        idx.observe_urls(urls.iter().copied());
        idx
    }

    pub fn observe_url(&self, raw: &str) {
        self.observe_urls(std::iter::once(raw));
    }

    /// Exclusive writer: lock, clone the frozen snapshot, mutate, `store`.
    /// Readers never take this lock. A scan burst cannot CAS-spin the core.
    pub fn observe_urls(&self, urls: impl IntoIterator<Item = impl AsRef<str>>) {
        if self.is_full() {
            return;
        }
        let batch: Vec<Vec<String>> = urls
            .into_iter()
            .filter_map(|u| {
                let segs = path_segments(u.as_ref());
                if segs.is_empty() {
                    None
                } else {
                    Some(segs)
                }
            })
            .collect();
        if batch.is_empty() {
            return;
        }
        let remaining = MAX_PATHS_PER_TENANT.saturating_sub(self.observes.load(Ordering::Relaxed));
        if remaining == 0 {
            return;
        }
        let take = batch.len().min(remaining);
        let _guard = self.write.lock().unwrap_or_else(|p| p.into_inner());
        let remaining = MAX_PATHS_PER_TENANT.saturating_sub(self.observes.load(Ordering::Relaxed));
        if remaining == 0 {
            return;
        }
        let take = take.min(remaining);
        let current = self.root.load();
        let mut n = (**current).clone();
        for segs in batch.iter().take(take) {
            insert_path(&mut n, segs);
        }
        self.root.store(Arc::new(n));
        self.observes.fetch_add(take, Ordering::Relaxed);
    }

    fn is_full(&self) -> bool {
        self.observes.load(Ordering::Relaxed) >= MAX_PATHS_PER_TENANT
    }

    /// Rewrite variable positions. Local structural rules apply first; tenant
    /// fan-out fills the gaps those rules miss. Walks a frozen snapshot — never
    /// acquires a write lock.
    #[must_use]
    pub fn apply_segments(&self, segs: &[&str]) -> String {
        let last = segs.len().saturating_sub(1);
        let snap = self.root.load();
        let mut node: Option<&TrieNode> = Some(snap.as_ref());
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

const CLUSTER_TARGET_PAGE_SQL: &str = r#"SELECT DISTINCT target
             FROM weissman_finding_clusters
            WHERE tenant_id = $1
              AND target <> ''
              AND last_seen_at > NOW() - INTERVAL '90 days'
              AND target > $2
            ORDER BY target
            LIMIT $3"#;

const VULN_TARGET_PAGE_SQL: &str = r#"SELECT DISTINCT t
             FROM (
                SELECT COALESCE(
                    NULLIF(raw_data->>'target', ''),
                    NULLIF(raw_data->>'target_url', ''),
                    NULLIF(raw_data->'raw'->>'url', ''),
                    NULLIF(raw_data->'raw'->>'target_url', ''),
                    NULLIF(raw_data->>'url', '')
                ) AS t
                  FROM vulnerabilities
                 WHERE tenant_id = $1
                   AND COALESCE(last_seen_at, discovered_at) > NOW() - INTERVAL '90 days'
             ) s
            WHERE t IS NOT NULL AND t > $2
            ORDER BY t
            LIMIT $3"#;

async fn paginate_unique_targets(
    pool: &PgPool,
    tenant_id: i64,
    index: &PathTemplateIndex,
    sql: &str,
) -> bool {
    let mut cursor = String::new();
    let mut any_ok = false;
    loop {
        if index.is_full() {
            break;
        }
        let Ok(mut tx) = crate::db::begin_tenant_tx(pool, tenant_id).await else {
            return any_ok;
        };
        let rows = sqlx::query_scalar::<_, String>(sql)
            .bind(tenant_id)
            .bind(&cursor)
            .bind(PREWARM_BATCH)
            .fetch_all(&mut *tx)
            .await;
        let committed = tx.commit().await.is_ok();
        match rows {
            Ok(rows) => {
                any_ok = true;
                if rows.is_empty() {
                    break;
                }
                if let Some(last) = rows.last() {
                    cursor = last.clone();
                }
                let n = rows.len();
                index.observe_urls(rows);
                if n < PREWARM_BATCH as usize {
                    break;
                }
            }
            Err(e) => {
                tracing::warn!(
                    target: "path_templates",
                    tenant_id,
                    error = %e,
                    "unique-path page unavailable for trie pre-warm"
                );
                return any_ok && committed;
            }
        }
    }
    any_ok
}

async fn observe_persisted_targets(
    pool: &PgPool,
    tenant_id: i64,
    index: &PathTemplateIndex,
) -> bool {
    // One short tenant TX per 25k unique-path page. Never dump the full
    // jsonb history into the Axum heap; 90-day window + DISTINCT + keyset.
    let clusters = paginate_unique_targets(pool, tenant_id, index, CLUSTER_TARGET_PAGE_SQL).await;
    if index.is_full() {
        return clusters;
    }
    let vulns = paginate_unique_targets(pool, tenant_id, index, VULN_TARGET_PAGE_SQL).await;
    clusters || vulns
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
/// [`weissman_db::active_tenant_ids`] (never a raw `tenants` scan). Bounded
/// concurrency (`PREWARM_CONCURRENCY`) so thousands of tenants cannot stretch
/// boot past a Kubernetes liveness probe, and cannot open N pool clients at once.
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
    stream::iter(ids)
        .for_each_concurrent(PREWARM_CONCURRENCY, |tid| async move {
            let _ = index_for_tenant(pool, tid).await;
        })
        .await;
    tracing::info!(
        target: "path_templates",
        tenants = n,
        concurrency = PREWARM_CONCURRENCY,
        window = PREWARM_WINDOW_SQL,
        batch = PREWARM_BATCH,
        "path-template trie pre-warmed from unique 90-day cluster/finding targets"
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
            build_cluster_key_ctx(1, &public, "xss", "CWE-79", &hint, Some(&idx)),
            build_cluster_key_ctx(1, &admin, "xss", "CWE-79", &hint, Some(&idx))
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

    #[test]
    fn prewarm_sql_is_bounded_unique_90_day_pages() {
        for sql in [CLUSTER_TARGET_PAGE_SQL, VULN_TARGET_PAGE_SQL] {
            assert!(
                sql.contains("INTERVAL '90 days'"),
                "pre-warm must not scan unbounded history:\n{sql}"
            );
            assert!(
                sql.contains("LIMIT $3"),
                "pre-warm must page with LIMIT:\n{sql}"
            );
            assert!(
                sql.contains("DISTINCT"),
                "pre-warm must ingest unique paths only:\n{sql}"
            );
        }
        assert_eq!(PREWARM_BATCH, 25_000);
        assert_eq!(PREWARM_CONCURRENCY, 10);
        let src = include_str!("path_templates.rs");
        assert!(
            src.contains("for_each_concurrent(PREWARM_CONCURRENCY"),
            "pre-warm must fan out tenants with bounded concurrency, not a serial for-loop"
        );
    }

    #[test]
    fn concurrent_observe_does_not_lost_update() {
        // Same tenant, two writers, disjoint prefixes. The write mutex serializes
        // clone-modify-store so both sides land; readers never take the lock.
        for _ in 0..32 {
            let idx = Arc::new(PathTemplateIndex::new());
            let a = idx.clone();
            let b = idx.clone();
            let t1 = std::thread::spawn(move || {
                a.observe_urls([
                    "https://api.corp/api/v1/users/alice",
                    "https://api.corp/api/v1/users/bob",
                ]);
            });
            let t2 = std::thread::spawn(move || {
                b.observe_urls([
                    "https://api.corp/api/v1/orgs/acme",
                    "https://api.corp/api/v1/orgs/globex",
                ]);
            });
            t1.join().expect("users writer");
            t2.join().expect("orgs writer");
            let hint = IdentityHint::default();
            let users = normalize_target_ctx(
                "https://api.corp/api/v1/users/carol",
                &hint,
                Some(idx.as_ref()),
            );
            let orgs = normalize_target_ctx(
                "https://api.corp/api/v1/orgs/other",
                &hint,
                Some(idx.as_ref()),
            );
            assert_eq!(users, "https://api.corp/api/v1/users/{id}");
            assert_eq!(orgs, "https://api.corp/api/v1/orgs/{id}");
        }
    }

    #[test]
    fn rcu_reads_never_wait_on_observe() {
        let idx = Arc::new(PathTemplateIndex::from_urls(&[
            "https://api.corp/api/v1/users/alice",
            "https://api.corp/api/v1/users/bob",
        ]));
        let readers = idx.clone();
        let t = std::thread::spawn(move || {
            for _ in 0..2_000 {
                let _ = readers.apply_segments(&["api", "v1", "users", "carol"]);
            }
        });
        for i in 0..2_000 {
            idx.observe_url(&format!("https://api.corp/api/v1/users/u{i}"));
        }
        t.join().expect("reader thread");
        let carol = normalize_target_ctx(
            "https://api.corp/api/v1/users/carol",
            &IdentityHint::default(),
            Some(idx.as_ref()),
        );
        assert_eq!(carol, "https://api.corp/api/v1/users/{id}");
    }

    #[test]
    fn writers_serialize_via_mutex_not_cas_spin() {
        let src = include_str!("path_templates.rs");
        let impl_src = src.split("#[cfg(test)]").next().expect("impl before tests");
        assert!(
            impl_src.contains("write: Mutex<()>"),
            "trie writes must take a single-writer mutex"
        );
        assert!(
            impl_src.contains("self.root.store"),
            "exclusive writer stores the snapshot; no CAS retry loop"
        );
        assert!(
            !impl_src.contains(".rcu("),
            "rcu/CAS spin is forbidden on the observe path"
        );
    }
}
