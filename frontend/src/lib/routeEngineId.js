/**
 * @deprecated Static ROUTE_ENGINE_ID map eradicated — use engineC2/engineManifestRegistry.
 * This module is a backward-compatible facade over capability-based manifests.
 */
import {
  getManifestByRoute,
  getManifestByEngineId,
  getRegisteredEngineRoutes,
  resolveEngineIdFromRoute,
} from '../engineC2/engineManifestRegistry.js'

/** @deprecated Use getManifestByRoute */
export const ROUTE_ENGINE_ID = new Proxy(
  {},
  {
    get(_target, prop) {
      if (prop === 'toJSON' || prop === Symbol.toStringTag) return undefined
      const m = getManifestByRoute(String(prop))
      return m?.engine_id
    },
    ownKeys() {
      return getRegisteredEngineRoutes()
    },
    getOwnPropertyDescriptor(_target, prop) {
      const id = resolveEngineIdFromRoute(String(prop))
      if (id) return { enumerable: true, configurable: true, value: id }
      return undefined
    },
  },
)

export const ROUTE_ENGINE_ID_PARAM_PREFIX = [
  { prefix: '/digital-twin/', engine: 'digital_twin' },
  { prefix: '/timing-profiler/', engine: 'side_channel' },
]

export const ROUTE_ENGINE_ID_PREFIX = [
  { prefix: '/engines/top-tier/', engineFromParam: true },
  { prefix: '/engines/business/', engineFromParam: true },
  { prefix: '/engines/', engineFromParam: true },
]

export function resolveRouteEngineId(pathname) {
  return resolveEngineIdFromRoute(pathname)
}

export { getManifestByRoute, getManifestByEngineId }
