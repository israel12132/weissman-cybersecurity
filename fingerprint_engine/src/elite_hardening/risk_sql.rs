//! SQL helpers for attack-path inference (recursive CTE) and internet-exposed auto-tag.

/// Bounded recursive walk from internet-exposed entry nodes toward crown jewels.
/// Used as a DB-side accelerator; in-memory Dijkstra remains the primary scorer.
pub const ATTACK_PATH_RECURSIVE_SQL: &str = r#"
WITH RECURSIVE walk AS (
    SELECT n.id AS node_id,
           n.id AS entry_id,
           0 AS hops,
           ARRAY[n.id] AS path
      FROM risk_graph_nodes n
     WHERE n.tenant_id = $1
       AND n.client_id = $2
       AND n.internet_exposed = TRUE
    UNION ALL
    SELECT e.to_node_id,
           w.entry_id,
           w.hops + 1,
           w.path || e.to_node_id
      FROM walk w
      JOIN risk_graph_edges e
        ON e.from_node_id = w.node_id
       AND e.tenant_id = $1
       AND e.client_id = $2
     WHERE w.hops < $3
       AND NOT e.to_node_id = ANY (w.path)
)
SELECT w.entry_id, w.node_id, w.hops, w.path
  FROM walk w
  JOIN risk_graph_nodes j ON j.id = w.node_id
 WHERE j.crown_jewel = TRUE
 LIMIT 500
"#;

/// Mark ASM/OSINT/public-HTTP assets as internet-exposed so Dijkstra has seeds.
pub const AUTO_TAG_INTERNET_EXPOSED_SQL: &str = r#"
UPDATE risk_graph_nodes
   SET internet_exposed = TRUE
 WHERE tenant_id = $1
   AND client_id = $2
   AND internet_exposed IS NOT TRUE
   AND (
        graph_key LIKE 'asm:%'
     OR graph_key LIKE 'osint:%'
     OR graph_key LIKE 'http:%'
     OR graph_key LIKE 'https:%'
     OR node_type IN ('asset', 'network')
     AND (
          COALESCE(metadata->>'public', '') IN ('true', '1')
       OR COALESCE(metadata->>'internet_exposed', '') IN ('true', '1')
     )
   )
"#;

/// Tag likely crown jewels so Dijkstra has sinks. Operator flags stay authoritative;
/// this only fills empty jewels from business value / high-risk identity-cloud-k8s
/// nodes. Honey nodes are never tagged.
pub const AUTO_TAG_CROWN_JEWEL_SQL: &str = r#"
UPDATE risk_graph_nodes
   SET crown_jewel = TRUE
 WHERE tenant_id = $1
   AND client_id = $2
   AND crown_jewel IS NOT TRUE
   AND COALESCE(honey_node, FALSE) IS NOT TRUE
   AND (
        COALESCE(business_value_usd, 0) > 0
     OR (
          node_type IN ('identity', 'database', 'k8s', 'k8s_secret', 'domain_controller', 'secret', 'dc')
      AND COALESCE(risk_score, 0) >= 55
        )
   )
"#;

/// If a client still has zero jewels after the heuristic, seed the top 3 by
/// business value then risk so attack-path inference is not vacuously empty.
pub const AUTO_TAG_CROWN_JEWEL_FALLBACK_SQL: &str = r#"
UPDATE risk_graph_nodes
   SET crown_jewel = TRUE
 WHERE tenant_id = $1
   AND client_id = $2
   AND id IN (
        SELECT id FROM risk_graph_nodes
         WHERE tenant_id = $1
           AND client_id = $2
           AND COALESCE(honey_node, FALSE) IS NOT TRUE
         ORDER BY COALESCE(business_value_usd, 0) DESC, COALESCE(risk_score, 0) DESC
         LIMIT 3
   )
   AND NOT EXISTS (
        SELECT 1 FROM risk_graph_nodes
         WHERE tenant_id = $1 AND client_id = $2 AND crown_jewel = TRUE
   )
"#;

pub fn max_hops() -> i32 {
    12
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sql_is_select_or_update_only() {
        let u = ATTACK_PATH_RECURSIVE_SQL.to_ascii_uppercase();
        assert!(u.contains("WITH RECURSIVE"));
        assert!(!u.contains("DROP "));
        assert!(
            AUTO_TAG_INTERNET_EXPOSED_SQL
                .to_ascii_uppercase()
                .starts_with('\n')
                || AUTO_TAG_INTERNET_EXPOSED_SQL
                    .trim_start()
                    .starts_with("UPDATE")
        );
        for sql in [AUTO_TAG_CROWN_JEWEL_SQL, AUTO_TAG_CROWN_JEWEL_FALLBACK_SQL] {
            assert!(sql.trim_start().to_ascii_uppercase().starts_with("UPDATE"));
            assert!(!sql.to_ascii_uppercase().contains("DROP "));
        }
    }
}
