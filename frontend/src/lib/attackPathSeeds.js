/** True when Dijkstra cannot seed sinks because the snapshot has zero crown jewels. */
export function needsCrownJewelSeed(snapshot) {
  if (!snapshot) return false
  return Number(snapshot.jewel_count) === 0
}

/** Rank graph nodes for the operator jewel/entry toggle — jewels first, then risk. */
export function rankJewelCandidates(nodes, limit = 25) {
  return [...(nodes || [])]
    .filter((n) => !n.honey_node)
    .sort((a, b) => {
      const jewelDelta = Number(Boolean(b.crown_jewel)) - Number(Boolean(a.crown_jewel))
      if (jewelDelta) return jewelDelta
      const entryDelta = Number(Boolean(b.internet_exposed)) - Number(Boolean(a.internet_exposed))
      if (entryDelta) return entryDelta
      return (Number(b.risk_score) || 0) - (Number(a.risk_score) || 0)
    })
    .slice(0, limit)
}
