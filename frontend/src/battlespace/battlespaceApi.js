import { apiFetch } from '../utils/apiFetch'

export async function fetchBattlespaceTopology(clientId, { signal } = {}) {
  return apiFetch(`/api/battlespace/topology/${clientId}`, { signal })
}

export async function fetchShadowPreview({ clientId, techniqueId, goal, signal }) {
  return apiFetch('/api/battlespace/shadow-preview', {
    method: 'POST',
    body: {
      client_id: clientId,
      technique_id: techniqueId || undefined,
      goal: goal || 'impact:objective',
    },
    signal,
  })
}

export function findingMatchesNode(finding, nodeId) {
  if (finding == null || nodeId == null) return false
  const want = String(nodeId)
  const raw = finding.raw_data && typeof finding.raw_data === 'object' ? finding.raw_data : null
  const nested = finding.raw && typeof finding.raw === 'object' ? finding.raw : null
  const candidates = [
    finding.risk_node_id,
    raw?.risk_node_id,
    nested?.risk_node_id,
  ]
  return candidates.some((id) => id != null && String(id) === want)
}

export function evidenceFromCache(cachedFindings, nodeId) {
  if (!Array.isArray(cachedFindings)) return null
  return cachedFindings.filter((f) => findingMatchesNode(f, nodeId))
}

export async function fetchNodeEvidence(clientId, nodeId, { signal, cachedFindings, pageCache } = {}) {
  if (Array.isArray(cachedFindings)) {
    return evidenceFromCache(cachedFindings, nodeId)
  }
  if (Array.isArray(pageCache?.current)) {
    return pageCache.current.filter((f) => findingMatchesNode(f, nodeId))
  }
  const data = await apiFetch(`/api/findings?client_id=${clientId}&limit=500`, { signal })
  if (data?.ok === false || data?.unavailable) {
    throw new Error(data.detail || 'findings unavailable')
  }
  const list = Array.isArray(data) ? data : data?.findings || []
  if (pageCache) pageCache.current = list
  return list.filter((f) => findingMatchesNode(f, nodeId))
}
