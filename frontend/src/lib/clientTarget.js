import { ENGINES_BY_ID, TARGETLESS_ENGINE_IDS } from './enginesRegistry.js'

/** Extra scan IDs accepted by the API but not in the production registry. */
const EXTRA_TARGETLESS = new Set(['zero_day_radar'])

/** First scope URL for engine targets (https:// + primary domain). */
export function clientPrimaryTargetUrl(client) {
  if (!client) return ''
  let list = []
  const raw = client.domains
  if (Array.isArray(raw)) {
    list = raw.map(String).filter(Boolean)
  } else if (typeof raw === 'string') {
    try {
      const arr = JSON.parse(raw)
      list = Array.isArray(arr) ? arr.map(String).filter(Boolean) : []
    } catch {
      list = []
    }
  }
  const first = list[0] || client.primary_domain || client.domain || ''
  if (!first) return ''
  return first.startsWith('http') ? first.trim() : `https://${String(first).replace(/^\/+/, '')}`
}

/** Alias used across command-center hubs. */
export const firstClientTarget = clientPrimaryTargetUrl

/** Resolve client from id + list (or pass client object directly). */
export function resolveClient(clientId, clients) {
  if (!clients) return null
  if (!Array.isArray(clients)) return clients
  if (!clientId) return null
  return clients.find((c) => String(c.id) === String(clientId)) ?? null
}

/** Matches server `engine_requires_target` / enginesRegistry.js `requiresTarget`. */
export function engineRequiresTarget(engineId) {
  if (!engineId) return true
  if (TARGETLESS_ENGINE_IDS.has(engineId) || EXTRA_TARGETLESS.has(engineId)) return false
  const rec = ENGINES_BY_ID[engineId]
  if (rec && typeof rec.requiresTarget === 'boolean') return rec.requiresTarget
  return true
}

/** Engines that do not need a URL target (tenant/global / credentialed job). */
export function engineRunsWithoutTarget(engineId) {
  return !engineRequiresTarget(engineId)
}

/**
 * Resolve the target posted to POST /api/command-center/scan.
 *
 * Scoped/client-locked users bind to their assigned domain when the engine
 * requires a target — never a client picker. Targetless engines never fail
 * closed on an empty URL (assigned domain is still sent when present).
 */
export function resolveEnqueueTarget({
  engineId,
  target,
  client,
  clientScopeLocked = false,
} = {}) {
  const typed = String(target || '').trim()
  const assigned = clientPrimaryTargetUrl(client)
  if (!engineRequiresTarget(engineId)) {
    return typed || assigned || ''
  }
  if (typed) return typed
  if (clientScopeLocked || client) return assigned
  return ''
}
