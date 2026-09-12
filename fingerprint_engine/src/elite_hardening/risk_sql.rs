//! SQL helpers for attack-path inference (recursive CTE), internet-exposed
//! auto-tag, and crown-jewel auto-tag (never honey, never overwrite operator flags).

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
///
/// `risk_graph_nodes.metadata` is TEXT (not JSONB). Never use `->>` here.
/// Operator `internet_exposed_locked` nodes are left untouched.
pub const AUTO_TAG_INTERNET_EXPOSED_SQL: &str = r#"
UPDATE risk_graph_nodes
   SET internet_exposed = TRUE
 WHERE tenant_id = $1
   AND client_id = $2
   AND internet_exposed IS NOT TRUE
   AND COALESCE(internet_exposed_locked, FALSE) IS NOT TRUE
   AND (
        graph_key LIKE 'asm:%'
     OR graph_key LIKE 'osint:%'
     OR graph_key LIKE 'http:%'
     OR graph_key LIKE 'https:%'
     OR (
          node_type IN ('asset', 'network')
      AND replace(lower(COALESCE(metadata::text, '')), ' ', '')
          ~ '"(public|internet_exposed)":(true|1|"true"|"1")'
     )
   )
"#;

/// Heuristic crown-jewel tag so Dijkstra is not silently empty.
/// Never overwrites an operator-locked flag; never tags honey nodes.
/// `asset_value` is the 0..3 multiplier (see financial blast-radius migration).
pub const AUTO_TAG_CROWN_JEWEL_SQL: &str = r#"
UPDATE risk_graph_nodes
   SET crown_jewel = TRUE
 WHERE tenant_id = $1
   AND client_id = $2
   AND crown_jewel IS NOT TRUE
   AND COALESCE(crown_jewel_locked, FALSE) IS NOT TRUE
   AND COALESCE(honey_node, FALSE) IS NOT TRUE
   AND (
        node_type IN ('identity', 'ot', 'ics', 'k8s_cluster', 'k8s', 'llm')
     OR COALESCE(business_value_usd, 0) >= 100000
     OR COALESCE(asset_value, 0) >= 2.5
     OR lower(label) ~ '(vault|hsm|domain.?control|adfs|okta|payroll|historian|scada|sap|kube-apiserver|postgres-primary|payment|pci)'
     OR lower(graph_key) ~ '(vault|identity:|ot:|k8s:|crown)'
   )
"#;

/// If the heuristic tagged nothing usable, pick the single highest-value non-honey node.
/// A honey node with crown_jewel=TRUE does not count as a usable jewel.
pub const AUTO_TAG_CROWN_JEWEL_FALLBACK_SQL: &str = r#"
UPDATE risk_graph_nodes
   SET crown_jewel = TRUE
 WHERE id = (
   SELECT id FROM risk_graph_nodes
    WHERE tenant_id = $1 AND client_id = $2
      AND COALESCE(honey_node, FALSE) IS NOT TRUE
      AND COALESCE(crown_jewel_locked, FALSE) IS NOT TRUE
    ORDER BY COALESCE(business_value_usd, 0) DESC,
             COALESCE(asset_value, 0) DESC,
             COALESCE(risk_score, 0) DESC
    LIMIT 1
 )
 AND tenant_id = $1
 AND client_id = $2
 AND COALESCE(crown_jewel_locked, FALSE) IS NOT TRUE
 AND NOT EXISTS (
   SELECT 1 FROM risk_graph_nodes
    WHERE tenant_id = $1 AND client_id = $2
      AND crown_jewel = TRUE
      AND COALESCE(honey_node, FALSE) IS NOT TRUE
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
            let u = sql.to_ascii_uppercase();
            assert!(u.contains("UPDATE"));
            assert!(u.contains("CROWN_JEWEL"));
            assert!(!u.contains("DROP "));
            assert!(!u.contains("TRUNCATE"));
        }
    }

    #[test]
    fn crown_jewel_sql_never_tags_honey() {
        assert!(AUTO_TAG_CROWN_JEWEL_SQL.contains("honey_node"));
        assert!(AUTO_TAG_CROWN_JEWEL_FALLBACK_SQL.contains("honey_node"));
    }

    #[test]
    fn auto_tag_sql_is_text_metadata_safe_and_respects_locks() {
        assert!(
            !AUTO_TAG_INTERNET_EXPOSED_SQL.contains("->>"),
            "metadata is TEXT; jsonb ->> would abort the seed transaction"
        );
        assert!(AUTO_TAG_INTERNET_EXPOSED_SQL.contains("internet_exposed_locked"));
        assert!(AUTO_TAG_CROWN_JEWEL_SQL.contains("crown_jewel_locked"));
        assert!(AUTO_TAG_CROWN_JEWEL_SQL.contains(">= 2.5"));
        assert!(!AUTO_TAG_CROWN_JEWEL_SQL.contains(">= 80"));
        assert!(AUTO_TAG_CROWN_JEWEL_FALLBACK_SQL.contains("honey_node"));
        assert!(AUTO_TAG_CROWN_JEWEL_FALLBACK_SQL.contains("crown_jewel_locked"));
    }
}
