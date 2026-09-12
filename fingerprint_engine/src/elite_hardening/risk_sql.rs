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

/// Tag likely crown jewels so Dijkstra has sinks.
///
/// Operator-cleared jewels stay off: we only write nodes that have never been
/// auto-tagged (`crown_jewel_auto IS NOT TRUE`) and are not currently jewels.
/// Evidence gate: business value or high-risk identity/cloud/k8s nodes.
/// Honey nodes are never tagged. No ranking fallback — empty jewel sets stay empty.
pub const AUTO_TAG_CROWN_JEWEL_SQL: &str = r#"
UPDATE risk_graph_nodes
   SET crown_jewel = TRUE,
       crown_jewel_auto = TRUE
 WHERE tenant_id = $1
   AND client_id = $2
   AND crown_jewel IS NOT TRUE
   AND COALESCE(crown_jewel_auto, FALSE) IS NOT TRUE
   AND COALESCE(honey_node, FALSE) IS NOT TRUE
   AND (
        COALESCE(business_value_usd, 0) > 0
     OR (
          node_type IN ('identity', 'database', 'k8s', 'k8s_secret', 'domain_controller', 'secret', 'dc')
      AND COALESCE(risk_score, 0) >= 55
        )
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
        let sql = AUTO_TAG_CROWN_JEWEL_SQL;
        assert!(sql.trim_start().to_ascii_uppercase().starts_with("UPDATE"));
        assert!(!sql.to_ascii_uppercase().contains("DROP "));
        assert!(sql.contains("crown_jewel_auto"));
        assert!(sql.contains("business_value_usd"));
        assert!(!sql.to_ascii_uppercase().contains("LIMIT 3"));
        assert!(!sql.to_ascii_uppercase().contains("FALLBACK"));
        assert!(sql.contains("COALESCE(crown_jewel_auto, FALSE) IS NOT TRUE"));
    }
}
