/** Pure helpers for Attack Paths — kept out of the page module so tests do not load C2 chrome. */

export function filterGraphNodes(graphNodes, nodeQuery) {
  const q = String(nodeQuery || '').trim().toLowerCase()
  return (Array.isArray(graphNodes) ? graphNodes : []).filter((n) => {
    if (!q) return true
    const label = String(n.label || n.name || n.graph_key || '')
    return (
      label.toLowerCase().includes(q) || String(n.node_type || '').toLowerCase().includes(q)
    )
  })
}
