/**
 * Unified engine parameter resolution — generated profiles loaded on demand.
 */
import { EXPLICIT_PARAM_DEFS } from './engineParamDefsExplicit.js'
import { GROUP_PARAMS } from './engineParamDefsGroups.js'
import { getAllManifests } from '../engineC2/engineManifestRegistry.js'
import { getGeneratedParamDefsSync, loadGeneratedParamDefs, prefetchEngineParamDefs } from './engineParamDefsLoader.js'

/** Command center route for an engine (from capability manifests). */
export const ENGINE_COMMAND_CENTER_ROUTES = Object.fromEntries(
  getAllManifests().flatMap((m) =>
    (m.route_paths || []).map((route) => [
      m.engine_id,
      route.startsWith('/') ? route : `/${route}`,
    ]),
  ),
)

Object.assign(ENGINE_COMMAND_CENTER_ROUTES, {
  xxe: '/engines/xxe',
  prototype_pollution: '/engines/prototype_pollution',
  liminal_boundary: '/engines/liminal_boundary',
  template_engine: '/template-engine',
  semantic_ai_fuzz: '/ast-fuzzing',
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

function resolveFromGenerated(id, generated) {
  if (!generated) return null
  const defs = generated[id]
  return defs?.length ? defs : null
}

/**
 * Resolve parameter schema — explicit/group immediately; generated when chunk is loaded.
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
  const generated = resolveFromGenerated(id, getGeneratedParamDefsSync())
  if (generated?.length) return generated
  const grp = GROUP_PARAMS[engine.group] || GROUP_PARAMS.web || []
  if (grp.length) return grp
  return UNIVERSAL_FALLBACK
}

export async function getEngineParamsAsync(engine) {
  if (!engine?.id) return []
  const id = engine.id
  if (EXPLICIT_PARAM_DEFS[id]?.length) return getEngineParams(engine)
  const generated = await loadGeneratedParamDefs()
  const fromGen = resolveFromGenerated(id, generated)
  if (fromGen?.length) return fromGen
  return getEngineParams(engine)
}

export function prefetchEngineParamsForEngine(engineId) {
  if (!engineId || EXPLICIT_PARAM_DEFS[engineId]?.length) return
  prefetchEngineParamDefs()
}

export function getEngineParamKeys(engineId) {
  return getEngineParams({ id: engineId }).map((p) => p.key)
}

export function getCommandCenterRoute(engineId) {
  return ENGINE_COMMAND_CENTER_ROUTES[engineId] || null
}

export { EXPLICIT_PARAM_DEFS, GROUP_PARAMS, prefetchEngineParamDefs }
