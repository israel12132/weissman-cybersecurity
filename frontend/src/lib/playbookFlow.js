/**
 * Pure graph helpers for the @xyflow playbook canvas — kept separate from the
 * ReactFlow rendering so the node/edge wiring logic is unit-testable without a
 * WebGL/layout environment. Ids are derived from a caller-supplied counter (no
 * RNG) so results are deterministic.
 */

export const NODE_LABEL = {
  trigger: 'Trigger',
  action: 'Action',
  condition: 'Condition',
  delay: 'Delay',
  notify: 'Notify',
}

/** Build a ReactFlow node of the given palette `type`. */
export function makeNode(type, id, position = { x: 0, y: 0 }) {
  return {
    id: `n${id}`,
    type: 'playbook',
    position: { x: Number(position.x) || 0, y: Number(position.y) || 0 },
    data: { label: NODE_LABEL[type] || type, nodeType: type },
  }
}

/** Add an edge source→target if it doesn't already exist. */
export function connect(edges, source, target) {
  if (!source || !target || source === target) return edges
  const id = `e-${source}-${target}`
  if ((edges || []).some((e) => e.id === id)) return edges
  return [...(edges || []), { id, source, target }]
}

/** Remove a node and any edges touching it. */
export function removeNode(nodes, edges, id) {
  return {
    nodes: (nodes || []).filter((n) => n.id !== id),
    edges: (edges || []).filter((e) => e.source !== id && e.target !== id),
  }
}

const BLOCKED_WEBHOOK_HOSTS = new Set([
  '169.254.169.254',
  '169.254.169.253',
  'localhost',
  'metadata',
  'metadata.google.internal',
  'ip6-localhost',
  'ip6-loopback',
])

function isPrivateIpv4(host) {
  const m = host.match(/^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/)
  if (!m) return false
  const a = Number(m[1])
  const b = Number(m[2])
  if (a === 10 || a === 127 || a === 0) return true
  if (a === 192 && b === 168) return true
  if (a === 169 && b === 254) return true
  if (a === 172 && b >= 16 && b <= 31) return true
  return false
}

/** True when a playbook webhook/HTTP URL targets metadata, loopback, or RFC1918. */
export function isBlockedWebhookUrl(raw) {
  if (!raw || typeof raw !== 'string') return false
  const trimmed = raw.trim()
  if (!trimmed) return false
  let u
  try {
    u = new URL(trimmed)
  } catch {
    return true
  }
  if (u.protocol !== 'http:' && u.protocol !== 'https:') return true
  const host = (u.hostname || '').replace(/\.$/, '').toLowerCase()
  if (!host) return true
  if (BLOCKED_WEBHOOK_HOSTS.has(host)) return true
  if (host.endsWith('.internal') || host.endsWith('.localhost')) return true
  if (host === '::1' || host.startsWith('[::1]')) return true
  if (isPrivateIpv4(host)) return true
  return false
}

export function playbookActionsHaveBlockedWebhook(actions) {
  return (actions || []).some((a) => {
    const kind = String(a?.kind || '').toLowerCase()
    if (!['webhook', 'http_post', 'slack_notify'].includes(kind)) return false
    const url = a?.params?.url || a?.params?.webhook_url
    return url ? isBlockedWebhookUrl(url) : false
  })
}

/** Serialize the canvas to a compact, persistable playbook graph. */
export function serializeGraph(nodes, edges) {
  return {
    nodes: (nodes || []).map((n) => ({ id: n.id, type: n.data?.nodeType, position: n.position })),
    edges: (edges || []).map((e) => ({ source: e.source, target: e.target })),
  }
}
