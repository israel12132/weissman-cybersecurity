/**
 * Engine UI manifest registry — capability-based routing (replaces static ROUTE_ENGINE_ID).
 */
import seed from '../lib/engineUiManifests.seed.json' with { type: 'json' }
import { apiFetch } from '../lib/apiBase.js'

/** @type {import('./types').EngineUiManifest[]} */
let manifests = Array.isArray(seed.manifests) ? seed.manifests : []
/** @type {Map<string, import('./types').EngineUiManifest>} */
const byRoute = new Map()
/** @type {Map<string, import('./types').EngineUiManifest>} */
const byEngineId = new Map()
let fetchPromise = null
let provenance = null

function normalizeRoute(pathname) {
  if (!pathname) return '/'
  let p = pathname
  if (p.startsWith('/command-center')) {
    p = p.slice('/command-center'.length) || '/'
  }
  if (p.length > 1 && p.endsWith('/')) p = p.slice(0, -1)
  if (!p.startsWith('/')) p = `/${p}`
  return p || '/'
}

function rebuildIndexes() {
  byRoute.clear()
  byEngineId.clear()
  for (const m of manifests) {
    if (!m?.engine_id) continue
    byEngineId.set(m.engine_id, m)
    for (const raw of m.route_paths || []) {
      byRoute.set(normalizeRoute(raw), m)
    }
  }
}

rebuildIndexes()

/**
 * @param {import('./types').EngineManifestEnvelope} envelope
 */
function ingestEnvelope(envelope) {
  if (Array.isArray(envelope?.manifests) && envelope.manifests.length > 0) {
    manifests = envelope.manifests
    provenance = envelope.provenance ?? null
    rebuildIndexes()
  }
}

/** Bootstrap from API; falls back to compile-time seed on failure. */
export async function loadEngineManifests(force = false) {
  if (!force && fetchPromise) return fetchPromise
  fetchPromise = apiFetch('/api/engines/ui-manifests')
    .then((r) => (r.ok ? r.json() : null))
    .then((data) => {
      if (data?.manifests?.length) ingestEnvelope(data)
      return { manifests, provenance }
    })
    .catch(() => ({ manifests, provenance }))
    .finally(() => {
      fetchPromise = null
    })
  return fetchPromise
}

/** @returns {import('./types').EngineUiManifest[]} */
export function getAllManifests() {
  return manifests
}

/** @returns {import('./types').EngineUiManifest|null} */
export function getManifestByRoute(pathname) {
  const p = normalizeRoute(pathname)
  if (byRoute.has(p)) return byRoute.get(p) ?? null

  const prefixRules = [
    { prefix: '/engines/top-tier/', takeLast: true },
    { prefix: '/engines/business/', takeLast: true },
    { prefix: '/engines/', takeLast: false },
    { prefix: '/digital-twin/', takeLast: false, fixedEngine: 'digital_twin' },
    { prefix: '/timing-profiler/', takeLast: false, fixedEngine: 'side_channel' },
  ]

  for (const { prefix, takeLast, fixedEngine } of prefixRules) {
    if (!p.startsWith(prefix)) continue
    if (fixedEngine) return getManifestByEngineId(fixedEngine)
    const rest = p.slice(prefix.length)
    if (!rest) continue
    const engineId = takeLast ? rest.split('/').filter(Boolean).pop() : rest.split('/')[0]
    if (engineId) return getManifestByEngineId(engineId)
  }

  return null
}

/** @returns {import('./types').EngineUiManifest|null} */
export function getManifestByEngineId(engineId) {
  if (!engineId) return null
  if (byEngineId.has(engineId)) return byEngineId.get(engineId) ?? null
  return {
    engine_id: engineId,
    route_paths: [`/engines/${engineId}`],
    evidence_i18n_key: 'pages.engineDetail.evidence_notice',
    capabilities: {
      requires_target_input: true,
      requires_scan_dispatch: true,
      requires_agent_gate: true,
      requires_kill_switch: true,
      needs_live_telemetry: true,
    },
    chrome: { badge_color: '#22d3ee' },
  }
}

/** @deprecated Use getManifestByRoute — returns engine_id for backward compatibility. */
export function resolveEngineIdFromRoute(pathname) {
  return getManifestByRoute(pathname)?.engine_id ?? null
}

/** All registered engine hub routes (for build-time compliance). */
export function getRegisteredEngineRoutes() {
  return [...byRoute.keys()]
}

export function getManifestProvenance() {
  return provenance
}
