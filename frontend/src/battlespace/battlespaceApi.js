import { apiFetch } from '../lib/apiBase'

export async function fetchBattlespaceTopology(clientId) {
  const r = await apiFetch(`/api/battlespace/topology/${clientId}`)
  if (!r.ok) throw new Error(`topology ${r.status}`)
  return r.json()
}

export async function fetchStripsTechniques() {
  const r = await apiFetch('/api/battlespace/techniques')
  if (!r.ok) return { techniques: [] }
  return r.json()
}

export async function fetchShadowPreview({ clientId, techniqueId, goal }) {
  const r = await apiFetch('/api/battlespace/shadow-preview', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      client_id: clientId,
      technique_id: techniqueId || undefined,
      goal: goal || 'impact:objective',
    }),
  })
  const data = await r.json().catch(() => ({}))
  if (!r.ok) throw new Error(data.detail || `shadow ${r.status}`)
  return data
}

export async function fetchNodeEvidence(clientId, nodeId) {
  const r = await apiFetch(`/api/findings?client_id=${clientId}&limit=100`)
  if (!r.ok) return []
  const data = await r.json().catch(() => [])
  const list = Array.isArray(data) ? data : data?.findings || []
  return list.filter((f) => {
    const nid = f.risk_node_id ?? f.raw_data?.risk_node_id
    return String(nid) === String(nodeId)
  })
}
