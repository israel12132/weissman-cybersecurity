/**
 * Pure graph helpers for the @xyflow playbook canvas — kept separate from the
 * ReactFlow rendering so the node/edge wiring logic is unit-testable without a
 * WebGL/layout environment. Ids are derived from a caller-supplied counter (no
 * RNG) so results are deterministic.
 *
 * The backend SOAR contract is linear (`when {trigger} do [actions]`). The
 * canvas is a visual editor for that DSL: one trigger node plus persistable
 * action nodes, wired into an ordered list. Condition/delay nodes are visual
 * only and are not persisted.
 */

export const NODE_LABEL = {
  trigger: 'Trigger',
  action: 'Action',
  condition: 'Condition',
  delay: 'Delay',
  notify: 'Notify',
}

/** Finding statuses a `set_status` action may request (operator-coerced server-side). */
export const SET_STATUS_OPTIONS = ['OPEN', 'ACKNOWLEDGED', 'IN_PROGRESS', 'FIXED', 'FALSE_POSITIVE']

/**
 * Action kinds the builder persists — must stay in lock-step with
 * `fingerprint_engine/src/playbook_dsl.rs` ALLOWED_ACTION_KINDS.
 */
export const ACTION_KIND_CATALOG = [
  {
    kind: 'set_status',
    nodeType: 'action',
    defaultParams: { status: 'IN_PROGRESS' },
    fields: [{ key: 'status', input: 'select', options: SET_STATUS_OPTIONS }],
  },
  {
    kind: 'slack_notify',
    nodeType: 'notify',
    defaultParams: { url: '', template: '{{severity}}: {{title}} on {{target}}' },
    fields: [
      { key: 'url', input: 'text' },
      { key: 'channel', input: 'text' },
      { key: 'template', input: 'textarea' },
    ],
  },
  {
    kind: 'webhook',
    nodeType: 'action',
    defaultParams: { url: '', template: '{{title}}' },
    fields: [
      { key: 'url', input: 'text' },
      { key: 'template', input: 'textarea' },
    ],
  },
  {
    kind: 'http_post',
    nodeType: 'action',
    defaultParams: { url: '', body: {} },
    fields: [
      { key: 'url', input: 'text' },
      { key: 'body', input: 'json' },
    ],
  },
  {
    kind: 'open_pr',
    nodeType: 'action',
    defaultParams: { title: 'Auto-fix: {{title}}' },
    fields: [
      { key: 'repo', input: 'text' },
      { key: 'title', input: 'text' },
    ],
  },
  {
    kind: 'isolate_host',
    nodeType: 'action',
    defaultParams: { target: '{{target}}', duration_seconds: 900 },
    fields: [
      { key: 'target', input: 'text' },
      { key: 'duration_seconds', input: 'number' },
    ],
  },
  {
    kind: 'page_oncall',
    nodeType: 'notify',
    defaultParams: { team: 'sec-oncall', severity: '{{severity}}' },
    fields: [
      { key: 'team', input: 'text' },
      { key: 'severity', input: 'text' },
    ],
  },
  {
    kind: 'create_incident',
    nodeType: 'action',
    defaultParams: { short_description: '{{title}}', severity: '{{severity}}' },
    fields: [
      { key: 'short_description', input: 'text' },
      { key: 'severity', input: 'text' },
    ],
  },
]

const KIND_BY_ID = Object.fromEntries(ACTION_KIND_CATALOG.map((k) => [k.kind, k]))

const PALETTE_ALIASES = {
  trigger: { kind: 'trigger', nodeType: 'trigger', defaultParams: {} },
  action: KIND_BY_ID.set_status,
  notify: KIND_BY_ID.slack_notify,
  condition: { kind: 'condition', nodeType: 'condition', defaultParams: { test: 'kev' } },
  delay: { kind: 'delay', nodeType: 'delay', defaultParams: { seconds: 60 } },
}

export const VISUAL_ONLY_KINDS = new Set(['condition', 'delay'])

/** HTML5 drag payload for NodePalette → PlaybookCanvas. */
export const NODE_DRAG_MIME = 'application/weissman-node'
export const NODE_DRAG_TEXT_PREFIX = 'weissman-node:'

export const AUTO_LAYOUT = { x: 180, y: 24, stepY: 130 }

export function setNodeDragData(dataTransfer, type) {
  if (!dataTransfer || !type) return
  dataTransfer.setData(NODE_DRAG_MIME, type)
  dataTransfer.setData('text/plain', `${NODE_DRAG_TEXT_PREFIX}${type}`)
  dataTransfer.effectAllowed = 'copy'
}

export function readNodeDragType(dataTransfer) {
  if (!dataTransfer?.getData) return ''
  const custom = dataTransfer.getData(NODE_DRAG_MIME)
  if (custom) return custom
  const plain = dataTransfer.getData('text/plain') || ''
  if (plain.startsWith(NODE_DRAG_TEXT_PREFIX)) {
    return plain.slice(NODE_DRAG_TEXT_PREFIX.length)
  }
  return ''
}

export function kindMeta(type) {
  if (KIND_BY_ID[type]) return KIND_BY_ID[type]
  if (PALETTE_ALIASES[type]) return PALETTE_ALIASES[type]
  return { kind: type, nodeType: 'action', defaultParams: {} }
}

export function isPersistableAction(kind) {
  return Boolean(KIND_BY_ID[kind])
}

export function isTriggerNode(node) {
  const kind = node?.data?.kind || node?.kind || node?.type
  const nodeType = node?.data?.nodeType || node?.nodeType
  return kind === 'trigger' || nodeType === 'trigger'
}

/** Drop the layout blob so trigger matching / JSON editors see only the DSL. */
export function stripCanvas(trigger) {
  if (!trigger || typeof trigger !== 'object' || Array.isArray(trigger)) return {}
  const { _canvas, ...rest } = trigger
  return rest
}

export function logicalPlaybookKey(trigger, actions) {
  return JSON.stringify({ trigger: stripCanvas(trigger), actions: actions || [] })
}

/** Build a ReactFlow node of the given palette `type` or action kind. */
export function makeNode(type, id, position = { x: 0, y: 0 }, extra = {}) {
  const meta = kindMeta(type)
  const kind = extra.kind || meta.kind
  const nodeType = extra.nodeType || meta.nodeType
  const params = extra.params !== undefined ? extra.params : { ...meta.defaultParams }
  const data = {
    label: extra.label || NODE_LABEL[nodeType] || kind,
    nodeType,
    kind,
  }
  if (kind === 'trigger') {
    data.trigger = extra.trigger && typeof extra.trigger === 'object' ? extra.trigger : {}
  } else {
    data.params = params
  }
  if (extra.summary != null) data.summary = extra.summary
  return {
    id: extra.id || `n${id}`,
    type: 'playbook',
    position: { x: Number(position.x) || 0, y: Number(position.y) || 0 },
    data,
  }
}

export function nextNumericId(nodes) {
  let max = 0
  for (const n of nodes || []) {
    const m = /^n(\d+)$/.exec(String(n.id || ''))
    if (m) max = Math.max(max, Number(m[1]))
  }
  return max + 1
}

function adjacency(edges) {
  const outgoing = {}
  for (const e of edges || []) {
    if (!e?.source || !e?.target) continue
    ;(outgoing[e.source] ||= []).push(e)
  }
  return outgoing
}

function sortOutgoing(edges, nodesById) {
  return [...edges].sort((a, b) => {
    const na = nodesById[a.target]
    const nb = nodesById[b.target]
    const dy = (na?.position?.y || 0) - (nb?.position?.y || 0)
    if (dy !== 0) return dy
    return (na?.position?.x || 0) - (nb?.position?.x || 0)
  })
}

/** Add an edge source→target if it doesn't already exist. */
export function connect(edges, source, target, extra = {}) {
  if (!source || !target || source === target) return edges
  const handleKey = extra.sourceHandle ? `:${extra.sourceHandle}` : ''
  const id = extra.id || `e-${source}-${target}${handleKey}`
  if ((edges || []).some((e) => e.id === id || (e.source === source && e.target === target && (e.sourceHandle || '') === (extra.sourceHandle || '')))) {
    return edges
  }
  return [...(edges || []), { id, source, target, ...extra }]
}

export function wouldCreateCycle(edges, source, target) {
  if (!source || !target || source === target) return true
  const outgoing = adjacency(edges)
  const stack = [target]
  const seen = new Set()
  while (stack.length) {
    const id = stack.pop()
    if (id === source) return true
    if (seen.has(id)) continue
    seen.add(id)
    for (const e of outgoing[id] || []) stack.push(e.target)
  }
  return false
}

export function graphHasCycle(nodes, edges) {
  const outgoing = adjacency(edges)
  const WHITE = 0
  const GRAY = 1
  const BLACK = 2
  const color = {}
  function dfs(id) {
    const c = color[id] || WHITE
    if (c === GRAY) return true
    if (c === BLACK) return false
    color[id] = GRAY
    for (const e of outgoing[id] || []) {
      if (dfs(e.target)) return true
    }
    color[id] = BLACK
    return false
  }
  for (const n of nodes || []) {
    if (dfs(n.id)) return true
  }
  return false
}

export function canConnect(nodes, edges, source, target) {
  if (!source || !target || source === target) return false
  const targetNode = (nodes || []).find((n) => n.id === target)
  if (isTriggerNode(targetNode)) return false
  if (wouldCreateCycle(edges, source, target)) return false
  return true
}

/** Remove a node and any edges touching it. */
export function removeNode(nodes, edges, id) {
  return {
    nodes: (nodes || []).filter((n) => n.id !== id),
    edges: (edges || []).filter((e) => e.source !== id && e.target !== id),
  }
}

export function removeEdge(edges, id) {
  return (edges || []).filter((e) => e.id !== id)
}

export function patchNode(nodes, id, dataPatch) {
  return (nodes || []).map((n) => {
    if (n.id !== id) return n
    return { ...n, data: { ...n.data, ...dataPatch } }
  })
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
    nodes: (nodes || []).map((n) => ({
      id: n.id,
      type: n.data?.nodeType,
      kind: n.data?.kind,
      position: n.position,
    })),
    edges: (edges || []).map((e) => ({
      source: e.source,
      target: e.target,
      ...(e.sourceHandle ? { sourceHandle: e.sourceHandle } : {}),
      ...(e.targetHandle ? { targetHandle: e.targetHandle } : {}),
    })),
  }
}

export function analyzeGraph(nodes, edges) {
  const list = nodes || []
  const triggers = list.filter(isTriggerNode)
  const nodesById = Object.fromEntries(list.map((n) => [n.id, n]))
  const outgoing = adjacency(edges)
  for (const src of Object.keys(outgoing)) {
    outgoing[src] = sortOutgoing(outgoing[src], nodesById)
  }

  const issues = []
  if (triggers.length === 0) issues.push({ level: 'error', code: 'no_trigger' })
  if (triggers.length > 1) issues.push({ level: 'error', code: 'multiple_triggers' })
  if (graphHasCycle(list, edges)) issues.push({ level: 'error', code: 'cycle' })

  const triggerNode = triggers[0] || null
  const visited = new Set()
  const ordered = []
  const visualSkipped = []

  function walk(id) {
    if (!id || visited.has(id)) return
    visited.add(id)
    const n = nodesById[id]
    if (!n) return
    const kind = n.data?.kind
    if (isPersistableAction(kind)) ordered.push(n)
    else if (VISUAL_ONLY_KINDS.has(kind)) visualSkipped.push(n)
    for (const e of outgoing[id] || []) walk(e.target)
  }
  if (triggerNode) walk(triggerNode.id)

  const orphans = list.filter((n) => isPersistableAction(n.data?.kind) && !visited.has(n.id))
    .sort((a, b) => (a.position?.y || 0) - (b.position?.y || 0) || (a.position?.x || 0) - (b.position?.x || 0))

  if (orphans.length) issues.push({ level: 'warning', code: 'orphans', count: orphans.length })
  if (visualSkipped.length) {
    issues.push({ level: 'warning', code: 'visual_only', count: visualSkipped.length })
  }

  return { triggerNode, ordered, orphans, visualSkipped, issues, triggers }
}

export function validatePlaybookGraph(nodes, edges) {
  const { issues } = analyzeGraph(nodes, edges)
  return {
    ok: !issues.some((i) => i.level === 'error'),
    issues,
  }
}

/**
 * Compile the canvas into the backend playbook DSL. Layout is stored on
 * `trigger._canvas` (ignored by the Rust matcher; round-tripped by GET/PATCH).
 */
export function flowToDsl(nodes, edges) {
  const { triggerNode, ordered, orphans, issues } = analyzeGraph(nodes, edges)
  const trigger = { ...(triggerNode?.data?.trigger || {}) }
  const actions = [...ordered, ...orphans]
    .filter((n) => isPersistableAction(n.data?.kind))
    .map((n) => ({
      kind: n.data.kind,
      params: n.data.params && typeof n.data.params === 'object' ? n.data.params : {},
    }))
  trigger._canvas = serializeGraph(nodes, edges)
  return { trigger, actions, issues }
}

function restoreFromCanvas(trigger, actions) {
  const canvas = trigger?._canvas
  if (!canvas || !Array.isArray(canvas.nodes) || canvas.nodes.length === 0) return null
  const flowNodes = canvas.nodes.map((n, i) => {
    const type = n.kind || n.type || 'action'
    return makeNode(type, i + 1, n.position || { x: 0, y: 0 }, { id: n.id || `n${i + 1}` })
  })
  const flowEdges = (canvas.edges || []).map((e, i) => ({
    id: e.id || `e-${e.source}-${e.target}-${i}`,
    source: e.source,
    target: e.target,
    ...(e.sourceHandle ? { sourceHandle: e.sourceHandle } : {}),
    ...(e.targetHandle ? { targetHandle: e.targetHandle } : {}),
  }))
  const { triggerNode, ordered, orphans } = analyzeGraph(flowNodes, flowEdges)
  if (!triggerNode) return null
  const walked = [...ordered, ...orphans]
  const acts = actions || []
  if (walked.length !== acts.length) return null
  for (let i = 0; i < walked.length; i += 1) {
    if (walked[i].data?.kind !== acts[i]?.kind) return null
  }
  const patched = flowNodes.map((n) => {
    if (isTriggerNode(n)) {
      return { ...n, data: { ...n.data, trigger: stripCanvas(trigger) } }
    }
    const idx = walked.findIndex((w) => w.id === n.id)
    if (idx < 0) return n
    return { ...n, data: { ...n.data, params: acts[idx]?.params || {} } }
  })
  return { nodes: patched, edges: flowEdges }
}

export function autoLayoutFlow(trigger, actions) {
  const nodes = [
    makeNode('trigger', 1, { x: AUTO_LAYOUT.x, y: AUTO_LAYOUT.y }, { trigger: stripCanvas(trigger) }),
  ]
  const edges = []
  let prev = nodes[0].id
  ;(actions || []).forEach((a, i) => {
    const n = makeNode(a.kind || 'set_status', i + 2, {
      x: AUTO_LAYOUT.x,
      y: AUTO_LAYOUT.y + (i + 1) * AUTO_LAYOUT.stepY,
    }, { params: a.params || {} })
    nodes.push(n)
    edges.push({ id: `e-${prev}-${n.id}`, source: prev, target: n.id })
    prev = n.id
  })
  return { nodes, edges }
}

/** Hydrate a ReactFlow graph from the persisted playbook DSL. */
export function dslToFlow(trigger, actions) {
  return restoreFromCanvas(trigger, actions) || autoLayoutFlow(trigger, actions)
}

export function nodeTitleKey(data) {
  const kind = data?.kind
  if (kind && KIND_BY_ID[kind]) return `playbooks.action.${kind}`
  const nodeType = data?.nodeType || 'action'
  return `playbooks.nodes.${nodeType}`
}

export function summarizeTrigger(trigger, anyLabel = 'any') {
  const t = trigger || {}
  const sev = Array.isArray(t.severity) && t.severity.length ? t.severity.join(', ') : anyLabel
  const flags = []
  if (t.kev) flags.push('KEV')
  if (t.exposed) flags.push('exposed')
  if (t.epss_min != null && t.epss_min !== '') flags.push(`epss≥${t.epss_min}`)
  return `severity: ${sev}${flags.length ? ` · ${flags.join(' · ')}` : ''}`
}

export function summarizeAction(kind, params = {}) {
  if (kind === 'set_status') return params.status || ''
  if (kind === 'isolate_host') return params.target || ''
  if (kind === 'page_oncall') return params.team || ''
  if (kind === 'open_pr') return params.repo || params.title || ''
  if (kind === 'create_incident') return params.short_description || ''
  if (kind === 'http_post' || kind === 'webhook' || kind === 'slack_notify') {
    const url = params.url || params.webhook_url || ''
    if (!url) return ''
    try {
      return new URL(url).host
    } catch {
      return url
    }
  }
  return ''
}
