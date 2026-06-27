/**
 * Unified engine parameter resolution for EngineDetail, TopTier profiles, and catalog.
 */
import { EXPLICIT_PARAM_DEFS } from './engineParamDefsExplicit.js'
import { GROUP_PARAMS } from './engineParamDefsGroups.js'
import { GENERATED_PARAM_DEFS } from './engineParamDefs.generated.js'
import { ROUTE_ENGINE_ID } from './routeEngineId.js'

/** Command center route for an engine (inverse of routeEngineId map + extras). */
export const ENGINE_COMMAND_CENTER_ROUTES = Object.fromEntries(
  Object.entries(ROUTE_ENGINE_ID).map(([route, id]) => [id, route.startsWith('/') ? route : `/${route}`]),
)

// Additional hubs not in ROUTE_ENGINE_ID
Object.assign(ENGINE_COMMAND_CENTER_ROUTES, {
  xxe: '/engines/xxe',
  ssti: '/template-engine',
  prototype_pollution: '/engines/prototype_pollution',
  liminal_boundary: '/engines/liminal_boundary',
  cache_poisoning: '/cache-posture',
  email_dns_posture: '/email-posture',
  bgp_dns_hijacking: '/dns-posture',
  edr_evasion: '/detection-surface',
  threat_emulation: '/threat-emulation',
  supply_chain: '/supply-chain',
  scada_ics: '/ot-ics',
  chronos: '/sovereign-defense-matrix',
  liquid_matrix: '/sovereign-defense-matrix',
  cognitive_starvation: '/sovereign-defense-matrix',
})

const UNIVERSAL_FALLBACK = [
  { key: 'intensity', label: 'Scan Intensity', type: 'select', options: ['light', 'normal', 'aggressive'], defaultVal: 'normal' },
  { key: 'max_findings', label: 'Max Findings', type: 'number', placeholder: '200', defaultVal: '200', min: 1, max: 5000 },
]

function mergeParams(...lists) {
  const seen = new Set()
  const out = []
  for (const list of lists) {
    for (const p of list || []) {
      if (!p?.key || seen.has(p.key)) continue
      seen.add(p.key)
      out.push(p)
    }
  }
  return out
}

/**
 * Resolve full parameter schema for an engine registry entry.
 * Priority: explicit > generated > group > universal fallback.
 */
export function getEngineParams(engine) {
  if (!engine?.id) return []
  const id = engine.id
  const explicit = EXPLICIT_PARAM_DEFS[id]
  if (explicit?.length) {
    const grp = GROUP_PARAMS[engine.group] || []
    const idKeys = new Set(explicit.map((p) => p.key))
    return mergeParams(explicit, grp.filter((p) => !idKeys.has(p.key)))
  }
  const generated = GENERATED_PARAM_DEFS[id]
  if (generated?.length) return generated
  const grp = GROUP_PARAMS[engine.group] || GROUP_PARAMS.web || []
  if (grp.length) return grp
  return UNIVERSAL_FALLBACK
}

export function getEngineParamKeys(engineId) {
  return getEngineParams({ id: engineId }).map((p) => p.key)
}

export function getCommandCenterRoute(engineId) {
  return ENGINE_COMMAND_CENTER_ROUTES[engineId] || null
}

export { EXPLICIT_PARAM_DEFS, GROUP_PARAMS, GENERATED_PARAM_DEFS }
