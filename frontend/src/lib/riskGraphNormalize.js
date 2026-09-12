/** Map a 0–100 graph risk_score onto the cockpit severity vocabulary. */
export function severityFromRisk(score) {
  const n = Number(score) || 0
  if (n >= 80) return 'critical'
  if (n >= 60) return 'high'
  if (n >= 30) return 'medium'
  return 'low'
}

/**
 * Normalize GET /api/clients/:id/risk-graph (and the /api/risk/graph alias)
 * so the canvas can render live path flags and edges.
 */
export function normalizeRiskGraph(payload) {
  const nodes = (payload?.nodes || []).map((n) => ({
    ...n,
    name: n.name || n.label,
    crown_jewel: Boolean(n.crown_jewel),
    internet_exposed: Boolean(n.internet_exposed),
    honey_node: Boolean(n.honey_node),
    severity: n.severity || severityFromRisk(n.risk_score),
  }))
  const edges = (payload?.edges || []).map((e) => ({
    ...e,
    source: e.source ?? e.from_node_id,
    target: e.target ?? e.to_node_id,
  }))
  return { nodes, edges }
}
