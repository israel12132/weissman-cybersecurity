//! Persistent unbounded discovery corpus (`intel.discovery_knowledge`).
//!
//! Every seed path/prefix, every live-LLM proposal, and every confirmed probe/DNS hit
//! is upserted so the next scan starts from a strictly larger knowledge base.

use sqlx::{PgPool, Row};
use weissman_engines::discovery_corpus::{
    all_http_paths, all_subdomain_prefixes, normalize_http_path, normalize_subdomain_prefix,
};

const KIND_PATH: &str = "path";
const KIND_SUB: &str = "subdomain_prefix";

#[derive(Debug, Clone, Default)]
pub struct CorpusStats {
    pub path_count: i64,
    pub subdomain_count: i64,
    pub llm_count: i64,
    pub confirmed_count: i64,
    pub seed_count: i64,
}

/// Upsert values. Empty / invalid entries are dropped. Never errors the scan.
pub async fn remember(
    pool: &PgPool,
    kind: &str,
    values: &[String],
    source: &str,
    confirmed: bool,
    tech_hint: &str,
) {
    if values.is_empty() {
        return;
    }
    let kind = match kind {
        KIND_PATH | KIND_SUB => kind,
        _ => return,
    };
    let hint = tech_hint.trim();
    let source = if source.trim().is_empty() {
        "live"
    } else {
        source.trim()
    };
    for raw in values {
        let Some(value) = normalize_value(kind, raw) else {
            continue;
        };
        if let Err(e) = sqlx::query(
            r#"INSERT INTO intel.discovery_knowledge
                   (kind, value, tech_hint, source, confirmed, hit_count, first_seen_at, last_seen_at)
               VALUES ($1, $2, $3, $4, $5, 1, now(), now())
               ON CONFLICT (kind, value_key, tech_hint)
               DO UPDATE SET
                   last_seen_at = now(),
                   hit_count = intel.discovery_knowledge.hit_count + 1,
                   confirmed = intel.discovery_knowledge.confirmed OR EXCLUDED.confirmed,
                   source = CASE
                       WHEN intel.discovery_knowledge.source = 'seed' THEN intel.discovery_knowledge.source
                       ELSE EXCLUDED.source
                   END"#,
        )
        .bind(kind)
        .bind(&value)
        .bind(hint)
        .bind(source)
        .bind(confirmed)
        .execute(pool)
        .await
        {
            tracing::debug!(
                target: "discovery_knowledge",
                error = %e,
                kind,
                value,
                "upsert skipped"
            );
        }
    }
}

fn normalize_value(kind: &str, raw: &str) -> Option<String> {
    if kind == KIND_PATH {
        normalize_http_path(raw)
    } else {
        normalize_subdomain_prefix(raw)
    }
}

/// Load stored values for a kind, confirmed hits first. No row cap — the corpus is unbounded.
pub async fn load(pool: &PgPool, kind: &str) -> Vec<String> {
    let rows = sqlx::query(
        r#"SELECT value FROM intel.discovery_knowledge
           WHERE kind = $1
           ORDER BY confirmed DESC, hit_count DESC, last_seen_at DESC"#,
    )
    .bind(kind)
    .fetch_all(pool)
    .await;
    match rows {
        Ok(rows) => rows
            .into_iter()
            .filter_map(|r| r.try_get::<String, _>("value").ok())
            .collect(),
        Err(e) => {
            tracing::debug!(target: "discovery_knowledge", error = %e, kind, "load skipped");
            vec![]
        }
    }
}

pub async fn load_paths(pool: &PgPool) -> Vec<String> {
    load(pool, KIND_PATH).await
}

pub async fn load_subdomain_prefixes(pool: &PgPool) -> Vec<String> {
    load(pool, KIND_SUB).await
}

/// Learned + confirmed values only (excludes unconfirmed public seed rows).
/// Use this when feeding HTTP engines so the 40k+ combinator seed is not dumped
/// into every fuzzer as `discovered_paths`.
pub async fn load_learned(pool: &PgPool, kind: &str) -> Vec<String> {
    let rows = sqlx::query(
        r#"SELECT value FROM intel.discovery_knowledge
           WHERE kind = $1 AND (source <> 'seed' OR confirmed)
           ORDER BY confirmed DESC, hit_count DESC, last_seen_at DESC"#,
    )
    .bind(kind)
    .fetch_all(pool)
    .await;
    match rows {
        Ok(rows) => rows
            .into_iter()
            .filter_map(|r| r.try_get::<String, _>("value").ok())
            .collect(),
        Err(e) => {
            tracing::debug!(target: "discovery_knowledge", error = %e, kind, "load_learned skipped");
            vec![]
        }
    }
}

pub async fn load_learned_paths(pool: &PgPool) -> Vec<String> {
    load_learned(pool, KIND_PATH).await
}

pub async fn stats(pool: &PgPool) -> CorpusStats {
    let row = sqlx::query(
        r#"SELECT
               COUNT(*) FILTER (WHERE kind = 'path')::bigint AS path_count,
               COUNT(*) FILTER (WHERE kind = 'subdomain_prefix')::bigint AS subdomain_count,
               COUNT(*) FILTER (WHERE source = 'llm')::bigint AS llm_count,
               COUNT(*) FILTER (WHERE confirmed)::bigint AS confirmed_count,
               COUNT(*) FILTER (WHERE source = 'seed')::bigint AS seed_count
           FROM intel.discovery_knowledge"#,
    )
    .fetch_one(pool)
    .await;
    match row {
        Ok(r) => CorpusStats {
            path_count: r.try_get("path_count").unwrap_or(0),
            subdomain_count: r.try_get("subdomain_count").unwrap_or(0),
            llm_count: r.try_get("llm_count").unwrap_or(0),
            confirmed_count: r.try_get("confirmed_count").unwrap_or(0),
            seed_count: r.try_get("seed_count").unwrap_or(0),
        },
        Err(_) => CorpusStats::default(),
    }
}

/// Idempotent seed insert. Skips when the public seed is already loaded.
pub async fn seed_public_knowledge(pool: &PgPool) {
    let existing: i64 = sqlx::query_scalar(
        "SELECT COUNT(*)::bigint FROM intel.discovery_knowledge WHERE source = 'seed'",
    )
    .fetch_one(pool)
    .await
    .unwrap_or(0);
    if existing > 1_000 {
        return;
    }
    seed_kind_chunks(pool, KIND_PATH, all_http_paths()).await;
    seed_kind_chunks(pool, KIND_SUB, all_subdomain_prefixes()).await;
}

async fn seed_kind_chunks(pool: &PgPool, kind: &str, values: &[String]) {
    for chunk in values.chunks(400) {
        let vals: Vec<String> = chunk.to_vec();
        if let Err(e) = sqlx::query(
            r#"INSERT INTO intel.discovery_knowledge (kind, value, tech_hint, source)
               SELECT $1, x, '', 'seed' FROM UNNEST($2::text[]) AS x
               ON CONFLICT (kind, value_key, tech_hint) DO NOTHING"#,
        )
        .bind(kind)
        .bind(&vals)
        .execute(pool)
        .await
        {
            tracing::debug!(target: "discovery_knowledge", error = %e, kind, "seed chunk skipped");
        }
    }
}

/// Merge seed ∪ stored ∪ extra without dropping anything.
#[must_use]
pub fn merge_unique(chunks: &[&[String]]) -> Vec<String> {
    let mut seen = std::collections::HashSet::new();
    let mut out = Vec::new();
    for chunk in chunks {
        for v in *chunk {
            if seen.insert(v.clone()) {
                out.push(v.clone());
            }
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn merge_unique_preserves_order_and_dedups() {
        let a = vec!["/a".into(), "/b".into()];
        let b = vec!["/b".into(), "/c".into()];
        let m = merge_unique(&[&a, &b]);
        assert_eq!(m, vec!["/a", "/b", "/c"]);
    }

    #[test]
    fn normalize_value_paths() {
        assert_eq!(
            normalize_value("path", "/graphql").as_deref(),
            Some("/graphql")
        );
        assert!(normalize_value("path", "").is_none());
        assert_eq!(
            normalize_value("subdomain_prefix", "Staging-API").as_deref(),
            Some("staging-api")
        );
    }
}
