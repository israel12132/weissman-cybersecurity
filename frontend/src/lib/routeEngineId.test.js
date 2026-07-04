import { describe, it, expect } from 'vitest'
import { resolveRouteEngineId } from './routeEngineId'
import { getManifestByRoute, getRegisteredEngineRoutes } from '../engineC2/engineManifestRegistry'

describe('resolveRouteEngineId (manifest-backed)', () => {
  it('resolves hub routes from capability manifests', () => {
    expect(resolveRouteEngineId('/jwt-lab')).toBe('jwt_attack')
    expect(resolveRouteEngineId('/mobile-security')).toBe('mobile_attack')
    expect(resolveRouteEngineId('/command-center/waf-bypass')).toBe('waf_bypass')
  })

  it('resolves tooling hubs outside legacy static map', () => {
    expect(resolveRouteEngineId('/template-engine')).toBe('template_engine')
    expect(resolveRouteEngineId('/ast-fuzzing')).toBe('semantic_ai_fuzz')
  })

  it('resolves parametric engine profile routes', () => {
    expect(resolveRouteEngineId('/engines/wifi_attack_engine')).toBe('wifi_attack_engine')
    expect(resolveRouteEngineId('/engines/top-tier/jwt_attack')).toBe('jwt_attack')
    expect(resolveRouteEngineId('/engines/business/osint')).toBe('osint')
  })

  it('returns null for non-engine routes', () => {
    expect(resolveRouteEngineId('/billing')).toBeNull()
    expect(resolveRouteEngineId('/clients')).toBeNull()
    expect(resolveRouteEngineId('/agents')).toBeNull()
  })

  it('every registered manifest route resolves an engine_id', () => {
    for (const path of getRegisteredEngineRoutes()) {
      const id = resolveRouteEngineId(path)
      expect(id, path).toBeTruthy()
      expect(getManifestByRoute(path)?.engine_id).toBe(id)
    }
  })
})
