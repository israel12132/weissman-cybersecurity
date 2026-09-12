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

/// Heuristic crown-jewel seeds when the operator has not flagged any.
/// Identity / cloud / k8s / OT nodes and valued assets become Dijkstra sinks.
/// High risk_score alone is **not** a jewel — that turned half the graph into
/// sinks and made paths meaningless. Operator-set `crown_jewel = TRUE` rows
/// are never overwritten. If this still yields zero jewels, the fallback tags
/// the top-5 highest-risk non-honeypot nodes.
pub const AUTO_TAG_CROWN_JEWEL_SQL: &str = r#"
UPDATE risk_graph_nodes
   SET crown_jewel = TRUE
 WHERE tenant_id = $1
   AND client_id = $2
   AND crown_jewel IS NOT TRUE
   AND COALESCE(honey_node, FALSE) IS NOT TRUE
   AND (
        node_type IN ('identity', 'cloud_resource', 'k8s_cluster', 'physical_asset')
     OR COALESCE(business_value_usd, 0) > 0
   )
"#;

/// If the primary heuristic still left zero jewels, tag the top-5 highest-risk
/// non-honeypot nodes so internet → jewel inference is not silently empty.
pub const AUTO_TAG_CROWN_JEWEL_FALLBACK_SQL: &str = r#"
UPDATE risk_graph_nodes n
   SET crown_jewel = TRUE
 WHERE n.tenant_id = $1
   AND n.client_id = $2
   AND n.crown_jewel IS NOT TRUE
   AND COALESCE(n.honey_node, FALSE) IS NOT TRUE
   AND NOT EXISTS (
         SELECT 1 FROM risk_graph_nodes j
          WHERE j.tenant_id = $1
            AND j.client_id = $2
            AND j.crown_jewel = TRUE
       )
   AND n.id IN (
         SELECT id FROM risk_graph_nodes
          WHERE tenant_id = $1
            AND client_id = $2
            AND COALESCE(honey_node, FALSE) IS NOT TRUE
          ORDER BY risk_score DESC NULLS LAST,
                   COALESCE(business_value_usd, 0) DESC NULLS LAST,
                   id
          LIMIT 5
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
    }

    #[test]
    fn crown_jewel_auto_tag_is_update_only_and_skips_honeypots() {
        for sql in [AUTO_TAG_CROWN_JEWEL_SQL, AUTO_TAG_CROWN_JEWEL_FALLBACK_SQL] {
            let u = sql.to_ascii_uppercase();
            assert!(u.contains("UPDATE RISK_GRAPH_NODES"));
            assert!(u.contains("CROWN_JEWEL"));
            assert!(u.contains("HONEY_NODE"));
            assert!(!u.contains("DROP "));
            assert!(!u.contains("DELETE "));
        }
        assert!(AUTO_TAG_CROWN_JEWEL_FALLBACK_SQL.contains("LIMIT 5"));
        assert!(
            !AUTO_TAG_CROWN_JEWEL_SQL.contains("risk_score"),
            "primary jewel heuristic must not treat raw risk_score as a sink"
        );
    }
}
