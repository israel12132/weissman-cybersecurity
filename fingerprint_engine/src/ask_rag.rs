//! Internal Council/RAG retrieval for Ask Weissman — **not** the QueryPlan path.
//!
//! Hermetic pool split:
//!   * QueryPlan execution uses `weissman_ro` and the 6-table allow-list only.
//!   * Semantic memory (`supreme_council_memory`) is read here on the **app**
//!     pool with a fixed SQL template. The client cannot name the table, set
//!     `k`, or inject predicates. Caps: [`crate::ask_vector_caps::MAX_K`] and
//!     [`crate::ask_vector_caps::MAX_COSINE_DISTANCE`].
//!
//! Prompt injection that tells the planner to "query RAG tables" still fails
//! at compile time — those names are blocked on the NL allow-list and are
//! not GRANTed to `weissman_ro`.

use crate::ask_vector_caps::{clamp_k, neighbor_allowed, MAX_K};
use sqlx::{PgPool, Row};

/// Fixed ANN template. Placeholders are only `$1` tenant, `$2` embedding, `$3` k.
pub const PLANNER_RAG_SQL: &str = r#"
SELECT brief_excerpt, (embedding_vec <=> $2::vector) AS distance
  FROM supreme_council_memory
 WHERE tenant_id = $1
   AND embedding_vec IS NOT NULL
 ORDER BY embedding_vec <=> $2::vector
 LIMIT $3
"#;

/// Server-selected excerpts for the planner prompt. Empty when embeddings or
/// the app pool are unavailable — Ask still compiles a QueryPlan.
pub async fn planner_context(app_pool: &PgPool, tenant_id: i64, question: &str) -> Option<String> {
    if tenant_id <= 0 {
        return None;
    }
    let clipped: String = question.chars().take(4000).collect();
    let embed = match crate::embeddings::embed_one(&clipped).await {
        Ok(Some(v)) => v,
        _ => return None,
    };
    let qtext = crate::embeddings::vec_to_pg_text(&embed);
    let k = clamp_k(MAX_K);
    let mut tx = crate::db::begin_tenant_tx(app_pool, tenant_id).await.ok()?;
    let rows = sqlx::query(PLANNER_RAG_SQL)
        .bind(tenant_id)
        .bind(&qtext)
        .bind(k)
        .fetch_all(&mut *tx)
        .await
        .ok()?;
    let _ = tx.commit().await;

    let mut lines = Vec::new();
    for r in rows {
        let dist: f64 = r.try_get("distance").unwrap_or(f64::INFINITY);
        if !neighbor_allowed(dist) {
            continue;
        }
        let excerpt: String = r.try_get("brief_excerpt").unwrap_or_default();
        let clean = sanitize_excerpt(&excerpt);
        if clean.is_empty() {
            continue;
        }
        lines.push(format!("- {clean}"));
        if lines.len() as i64 >= k {
            break;
        }
    }
    if lines.is_empty() {
        return None;
    }
    Some(format!(
        "Server-selected council memory (not a queryable table; never put RAG/vector tables in the plan):\n{}",
        lines.join("\n")
    ))
}

fn sanitize_excerpt(s: &str) -> String {
    s.chars()
        .filter(|c| !c.is_control())
        .take(240)
        .collect::<String>()
        .trim()
        .to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn retrieval_sql_is_fixed_and_parameterised() {
        assert!(PLANNER_RAG_SQL.contains("supreme_council_memory"));
        assert!(PLANNER_RAG_SQL.contains("$1"));
        assert!(PLANNER_RAG_SQL.contains("$2::vector"));
        assert!(PLANNER_RAG_SQL.contains("LIMIT $3"));
        assert!(!PLANNER_RAG_SQL.contains('{'));
        assert!(
            !PLANNER_RAG_SQL.contains('\''),
            "no quoted literals — bind $1/$2/$3 only"
        );
        assert_eq!(clamp_k(99), MAX_K);
    }

    #[test]
    fn excerpts_are_control_stripped_and_capped() {
        let dirty = format!("ab\0c{}", "x".repeat(400));
        let out = sanitize_excerpt(&dirty);
        assert!(!out.contains('\0'));
        assert!(out.chars().count() <= 240);
        assert!(out.starts_with("abc"));
    }
}
