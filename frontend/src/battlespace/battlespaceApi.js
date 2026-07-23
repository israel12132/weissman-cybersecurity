import { apiFetch } from '../utils/apiFetch'

export async function fetchBattlespaceTopology(clientId) {
  return apiFetch(`/api/battlespace/topology/${clientId}`)
}

export async function fetchStripsTechniques() {
  try {
    return await apiFetch('/api/battlespace/techniques')
  } catch {
    return { techniques: [] }
  }
}

export async function fetchShadowPreview({ clientId, techniqueId, goal }) {
  return apiFetch('/api/battlespace/shadow-preview', {
    method: 'POST',
    body: {
      client_id: clientId,
      technique_id: techniqueId || undefined,
      goal: goal || 'impact:objective',
    },
  })
}

export async function fetchNodeEvidence(clientId, nodeId) {
  let data
  try {
    data = await apiFetch(`/api/findings?client_id=${clientId}&limit=100`)
  } catch {
    return []
  }
  const list = Array.isArray(data) ? data : data?.findings || []
  return list.filter((f) => {
    const nid = f.risk_node_id ?? f.raw_data?.risk_node_id
    return String(nid) === String(nodeId)
  })
}
