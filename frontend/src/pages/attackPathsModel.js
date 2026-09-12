/**
 * Pure helpers for GET /api/attack-paths/:id and PATCH crown-jewel flags.
 * Kept out of AttackPaths.jsx so unit tests do not import the page graph.
 */

export function parseAttackPathsPayload(data) {
  const snapshot = data?.snapshot || null
  return {
    snapshot,
    hasSnapshot: Boolean(snapshot),
    zeroJewel: Boolean(data?.zero_jewel) || Number(snapshot?.jewel_count) === 0,
    candidateJewels: Array.isArray(data?.candidate_jewels) ? data.candidate_jewels : [],
  }
}

export function crownJewelFlagsPath(nodeId) {
  return `/api/risk-graph/nodes/${encodeURIComponent(nodeId)}/flags`
}

export function crownJewelFlagsBody() {
  return { crown_jewel: true }
}
