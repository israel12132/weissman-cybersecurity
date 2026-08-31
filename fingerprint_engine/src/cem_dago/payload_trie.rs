//! Bounded payload/target prefix trie — CEM-DAGO historical memory.
//!
//! Enterprise tenants store millions of findings. Loading `SELECT raw_data, target
//! FROM …` with no `LIMIT` and no time window at process or scan start OOMs the
//! worker. Pre-warm **only the last 90 days**, in **25_000-row keyset pages**
//! (`id > $last_id`), and stop at a hard cap so even a huge 90-day window cannot
//! pin RAM.
//!
//! Keys are normalized target hosts (not full `raw_data` blobs). Payload text is
//! truncated. Hits seed the blackboard and `EngineRunContext.memory_payloads`.

use crate::pentest_memory::target_host_for_memory;
use serde::Serialize;
use sqlx::{PgPool, Row};
use std::collections::HashMap;

/// Keyset page size. Never raise without revisiting the hard cap.
pub const PREWARM_BATCH_SIZE: i64 = 25_000;
/// Rolling window loaded into the trie.
pub const PREWARM_WINDOW_DAYS: i64 = 90;
/// Safety valve if 90 days still contains millions of rows.
pub const PREWARM_HARD_CAP: usize = 250_000;
/// Max chars stored per payload in the trie (full blobs stay in Postgres).
pub const PAYLOAD_CHAR_CAP: usize = 512;
/// Cap hits stored on a single target node.
pub const HITS_PER_NODE_CAP: usize = 32;

/// Compact seed row extracted from findings / pentest memory — never a full JSONB blob.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TrieSeed {
    pub id: i64,
    pub target: String,
    pub engine: String,
    pub payload: String,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct TrieHit {
    pub engine: String,
    pub payload: String,
}

#[derive(Debug, Clone, Default)]
struct TrieNode {
    children: HashMap<u8, Box<TrieNode>>,
    hits: Vec<TrieHit>,
}

/// Prefix trie of historical winning payloads keyed by target host.
#[derive(Debug, Clone, Default)]
pub struct PayloadTrie {
    root: TrieNode,
    len: usize,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct PrewarmStats {
    pub pages_fetched: u32,
    pub rows_seen: usize,
    pub inserted: usize,
    pub hit_hard_cap: bool,
}

impl PayloadTrie {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    #[must_use]
    pub fn len(&self) -> usize {
        self.len
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    pub fn insert_seed(&mut self, seed: TrieSeed, hard_cap: usize) -> bool {
        if self.len >= hard_cap {
            return false;
        }
        let key = normalize_target(&seed.target);
        if key.is_empty() {
            return false;
        }
        let payload: String = seed.payload.chars().take(PAYLOAD_CHAR_CAP).collect();
        let engine = seed.engine;
        if payload.is_empty() && engine.is_empty() {
            return false;
        }
        let mut node = &mut self.root;
        for b in key.bytes() {
            node = node
                .children
                .entry(b)
                .or_insert_with(|| Box::new(TrieNode::default()));
        }
        if node.hits.len() >= HITS_PER_NODE_CAP {
            return false;
        }
        if node
            .hits
            .iter()
            .any(|h| h.payload == payload && h.engine == engine)
        {
            return false;
        }
        node.hits.push(TrieHit { engine, payload });
        self.len += 1;
        true
    }

    /// Hits whose stored target is a prefix of `target` (host walk).
    #[must_use]
    pub fn lookup_target(&self, target: &str) -> Vec<TrieHit> {
        let key = normalize_target(target);
        if key.is_empty() {
            return Vec::new();
        }
        let mut node = &self.root;
        let mut out = Vec::new();
        for b in key.bytes() {
            match node.children.get(&b) {
                Some(child) => {
                    node = child;
                    out.extend(node.hits.iter().cloned());
                }
                None => break,
            }
        }
        out
    }

    #[must_use]
    pub fn payloads_for_target(&self, target: &str) -> Vec<String> {
        self.lookup_target(target)
            .into_iter()
            .map(|h| h.payload)
            .filter(|p| !p.is_empty())
            .collect()
    }
}

fn normalize_target(raw: &str) -> String {
    target_host_for_memory(raw).to_ascii_lowercase()
}

/// Findings page: keyset (`id > $2`), 90-day window (`$3` days), `LIMIT $4`.
/// Extracts `raw_data->>'target'` — never `SELECT raw_data, target FROM` unbounded.
pub const FINDINGS_PREWARM_SQL: &str = r#"SELECT id,
              COALESCE(NULLIF(trim(raw_data->>'target'), ''), NULLIF(trim(title), ''), '') AS target,
              COALESCE(NULLIF(trim(raw_data->>'engine'), ''), NULLIF(trim(source), ''), '') AS engine,
              left(COALESCE(raw_data->>'payload', raw_data->>'poc', ''), 512) AS payload
         FROM vulnerabilities
        WHERE tenant_id = $1
          AND created_at >= NOW() - ($3::bigint * INTERVAL '1 day')
          AND id > $2
          AND ($5::bigint IS NULL OR client_id = $5)
        ORDER BY id
        LIMIT $4"#;

/// Pentest-memory page: same keyset + window + LIMIT contract.
pub const WINNING_PATHS_PREWARM_SQL: &str = r#"SELECT id,
              target_fingerprint AS target,
              engine,
              left(payload, 512) AS payload
         FROM pentest_winning_paths
        WHERE tenant_id = $1
          AND created_at >= NOW() - ($3::bigint * INTERVAL '1 day')
          AND id > $2
          AND ($5::bigint IS NULL OR TRUE)
        ORDER BY id
        LIMIT $4"#;

/// PoE gadget-chain page (intel.dynamic_payloads) — same batch size, no OFFSET.
pub const DYNAMIC_PAYLOADS_PREWARM_SQL: &str = r#"SELECT id, target_library, payload_data
         FROM dynamic_payloads
        WHERE added_at >= NOW() - INTERVAL '90 days'
          AND id > $1
        ORDER BY id
        LIMIT $2"#;

/// True when `sql` is a bounded keyset page (LIMIT + time window, no OFFSET).
#[must_use]
pub fn sql_is_bounded_prewarm(sql: &str) -> bool {
    let s = sql.to_ascii_uppercase();
    let has_limit = s.contains("LIMIT $") || s.contains("LIMIT 25000");
    let has_window = s.contains("INTERVAL")
        && (s.contains("90 DAYS") || s.contains("1 DAY") || s.contains("90 DAY"));
    let has_keyset = s.contains("ID > $");
    let no_offset = !s.contains("OFFSET");
    let not_unbounded_blob =
        !s.contains("SELECT RAW_DATA, TARGET FROM") && !s.contains("SELECT RAW_DATA , TARGET FROM");
    has_limit && has_window && has_keyset && no_offset && not_unbounded_blob
}

#[must_use]
pub fn prewarm_hard_cap() -> usize {
    std::env::var("WEISSMAN_CEM_DAGO_TRIE_HARD_CAP")
        .ok()
        .and_then(|s| s.trim().parse::<usize>().ok())
        .filter(|&n| n > 0)
        .unwrap_or(PREWARM_HARD_CAP)
        .min(PREWARM_HARD_CAP)
}

/// Ingest already-fetched pages (unit-tested without Postgres). Stops at `hard_cap`.
#[must_use]
pub fn ingest_pages(
    pages: impl IntoIterator<Item = Vec<TrieSeed>>,
    hard_cap: usize,
) -> (PayloadTrie, PrewarmStats) {
    let mut trie = PayloadTrie::new();
    let mut stats = PrewarmStats::default();
    for page in pages {
        if trie.len() >= hard_cap {
            stats.hit_hard_cap = true;
            break;
        }
        stats.pages_fetched += 1;
        if page.is_empty() {
            break;
        }
        stats.rows_seen += page.len();
        for seed in page {
            if !trie.insert_seed(seed, hard_cap) && trie.len() >= hard_cap {
                stats.hit_hard_cap = true;
                break;
            }
        }
        if trie.len() >= hard_cap {
            stats.hit_hard_cap = true;
            break;
        }
    }
    stats.inserted = trie.len();
    (trie, stats)
}

fn row_to_seed(r: &sqlx::postgres::PgRow) -> Option<TrieSeed> {
    let id: i64 = r.try_get("id").ok()?;
    Some(TrieSeed {
        id,
        target: r.try_get("target").unwrap_or_default(),
        engine: r.try_get("engine").unwrap_or_default(),
        payload: r.try_get("payload").unwrap_or_default(),
    })
}

async fn paginate_sql_into_trie(
    trie: &mut PayloadTrie,
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    sql: &str,
    tenant_id: i64,
    client_id: Option<i64>,
    stats: &mut PrewarmStats,
    hard_cap: usize,
) {
    let mut last_id: i64 = 0;
    loop {
        if trie.len() >= hard_cap {
            stats.hit_hard_cap = true;
            break;
        }
        let remaining = (hard_cap - trie.len()) as i64;
        let take = remaining.min(PREWARM_BATCH_SIZE).max(1);
        let rows = match sqlx::query(sql)
            .bind(tenant_id)
            .bind(last_id)
            .bind(PREWARM_WINDOW_DAYS)
            .bind(take)
            .bind(client_id)
            .fetch_all(&mut **tx)
            .await
        {
            Ok(r) => r,
            Err(e) => {
                tracing::warn!(
                    target: "cem_dago",
                    error = %e,
                    "payload trie pre-warm page failed (scan continues with partial trie)"
                );
                break;
            }
        };
        stats.pages_fetched += 1;
        if rows.is_empty() {
            break;
        }
        let n = rows.len();
        stats.rows_seen += n;
        for r in &rows {
            if let Some(seed) = row_to_seed(r) {
                last_id = last_id.max(seed.id);
                if !trie.insert_seed(seed, hard_cap) && trie.len() >= hard_cap {
                    stats.hit_hard_cap = true;
                    break;
                }
            } else if let Ok(id) = r.try_get::<i64, _>("id") {
                last_id = last_id.max(id);
            }
        }
        if trie.len() >= hard_cap {
            stats.hit_hard_cap = true;
            break;
        }
        if n < take as usize {
            break;
        }
    }
}

/// Load the last 90 days of compact target/payload rows into a trie. Fail-open:
/// a DB error yields an empty trie and the scan continues.
pub async fn prewarm_payload_trie(
    pool: &PgPool,
    tenant_id: i64,
    client_id: Option<i64>,
) -> (PayloadTrie, PrewarmStats) {
    let mut trie = PayloadTrie::new();
    let mut stats = PrewarmStats::default();
    if tenant_id <= 0 {
        return (trie, stats);
    }
    let hard_cap = prewarm_hard_cap();
    let Ok(mut tx) = crate::db::begin_tenant_tx(pool, tenant_id).await else {
        tracing::warn!(
            target: "cem_dago",
            tenant_id,
            "payload trie pre-warm skipped: tenant tx unavailable"
        );
        return (trie, stats);
    };

    paginate_sql_into_trie(
        &mut trie,
        &mut tx,
        FINDINGS_PREWARM_SQL,
        tenant_id,
        client_id,
        &mut stats,
        hard_cap,
    )
    .await;
    paginate_sql_into_trie(
        &mut trie,
        &mut tx,
        WINNING_PATHS_PREWARM_SQL,
        tenant_id,
        client_id,
        &mut stats,
        hard_cap,
    )
    .await;
    let _ = tx.commit().await;
    stats.inserted = trie.len();
    tracing::info!(
        target: "cem_dago",
        tenant_id,
        client_id = client_id.unwrap_or(0),
        pages = stats.pages_fetched,
        rows_seen = stats.rows_seen,
        inserted = stats.inserted,
        hit_hard_cap = stats.hit_hard_cap,
        window_days = PREWARM_WINDOW_DAYS,
        batch_size = PREWARM_BATCH_SIZE,
        "payload trie pre-warm complete"
    );
    (trie, stats)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn seed(id: i64, target: &str, engine: &str, payload: &str) -> TrieSeed {
        TrieSeed {
            id,
            target: target.into(),
            engine: engine.into(),
            payload: payload.into(),
        }
    }

    #[test]
    fn batch_and_window_constants() {
        assert_eq!(PREWARM_BATCH_SIZE, 25_000);
        assert_eq!(PREWARM_WINDOW_DAYS, 90);
        assert!(PREWARM_HARD_CAP >= PREWARM_BATCH_SIZE as usize);
    }

    #[test]
    fn findings_sql_is_keyset_paginated_90_days() {
        assert!(sql_is_bounded_prewarm(FINDINGS_PREWARM_SQL));
        let sql = FINDINGS_PREWARM_SQL.to_ascii_uppercase();
        assert!(sql.contains("LIMIT $4"), "must bind LIMIT, not fetch all");
        assert!(sql.contains("ID > $2"), "keyset pagination, not OFFSET");
        assert!(
            !sql.contains("OFFSET"),
            "OFFSET on millions of rows is the OOM/latency trap"
        );
        assert!(
            sql.contains("INTERVAL"),
            "90-day window must be in the WHERE clause"
        );
        assert!(
            !FINDINGS_PREWARM_SQL
                .replace(' ', "")
                .to_ascii_lowercase()
                .contains("selectraw_data,targetfrom"),
            "never SELECT raw_data, target FROM unbounded"
        );
    }

    #[test]
    fn winning_paths_sql_is_keyset_paginated_90_days() {
        assert!(sql_is_bounded_prewarm(WINNING_PATHS_PREWARM_SQL));
        assert!(WINNING_PATHS_PREWARM_SQL.contains("LIMIT $4"));
        assert!(WINNING_PATHS_PREWARM_SQL.contains("id > $2"));
        assert!(!WINNING_PATHS_PREWARM_SQL
            .to_ascii_uppercase()
            .contains("OFFSET"));
    }

    #[test]
    fn dynamic_payloads_sql_is_bounded() {
        assert!(sql_is_bounded_prewarm(DYNAMIC_PAYLOADS_PREWARM_SQL));
        assert!(DYNAMIC_PAYLOADS_PREWARM_SQL.contains("LIMIT $2"));
        assert!(DYNAMIC_PAYLOADS_PREWARM_SQL.contains("id > $1"));
        assert!(DYNAMIC_PAYLOADS_PREWARM_SQL.contains("90 days"));
        assert!(!DYNAMIC_PAYLOADS_PREWARM_SQL
            .to_ascii_uppercase()
            .contains("OFFSET"));
    }

    #[test]
    fn prefix_lookup_returns_historical_payload() {
        let mut trie = PayloadTrie::new();
        trie.insert_seed(
            seed(1, "https://api.acme.com/v1", "xss", "<script>"),
            PREWARM_HARD_CAP,
        );
        let hits = trie.lookup_target("https://api.acme.com/v1/users?id=1");
        assert!(hits.iter().any(|h| h.payload.contains("<script>")));
        assert!(hits.iter().any(|h| h.engine == "xss"));
        assert!(trie.lookup_target("other.example").is_empty());
    }

    #[test]
    fn pagination_stops_at_hard_cap_without_dropping_prior_pages() {
        let page1: Vec<TrieSeed> = (1..=3)
            .map(|i| seed(i, "api.acme.com", "xss", &format!("p{i}")))
            .collect();
        let page2: Vec<TrieSeed> = (4..=6)
            .map(|i| seed(i, "api.acme.com", "sqli", &format!("p{i}")))
            .collect();
        let page3: Vec<TrieSeed> = (7..=9)
            .map(|i| seed(i, "api.acme.com", "ssti", &format!("p{i}")))
            .collect();
        let (trie, stats) = ingest_pages(vec![page1, page2, page3], 5);
        assert_eq!(trie.len(), 5);
        assert!(stats.hit_hard_cap);
        assert!(stats.pages_fetched >= 2);
        assert!(stats.inserted <= 5);
        // First-page siblings survived the cap on a later page.
        let payloads = trie.payloads_for_target("api.acme.com");
        assert!(payloads.iter().any(|p| p == "p1"));
        assert!(payloads.iter().any(|p| p == "p2"));
    }

    #[test]
    fn ingest_exhausts_short_window() {
        let pages = vec![
            vec![seed(1, "a.test", "xss", "x")],
            vec![seed(2, "b.test", "xss", "y")],
            vec![],
        ];
        let (trie, stats) = ingest_pages(pages, PREWARM_HARD_CAP);
        assert_eq!(trie.len(), 2);
        assert!(!stats.hit_hard_cap);
        assert_eq!(stats.pages_fetched, 3);
    }

    #[test]
    fn rejected_unbounded_select_shape() {
        let bad = "SELECT raw_data, target FROM vulnerabilities WHERE tenant_id = $1";
        assert!(!sql_is_bounded_prewarm(bad));
    }
}
