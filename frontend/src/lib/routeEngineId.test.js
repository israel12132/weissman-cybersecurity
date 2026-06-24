import { describe, it, expect } from 'vitest'
import { resolveRouteEngineId, ROUTE_ENGINE_ID } from './routeEngineId'

describe('resolveRouteEngineId', () => {
  it('maps command-center hub routes to primary engine ids', () => {
    expect(resolveRouteEngineId('/jwt-lab')).toBe('jwt_attack')
    expect(resolveRouteEngineId('/mobile-security')).toBe('mobile_attack')
    expect(resolveRouteEngineId('/command-center/waf-bypass')).toBe('waf_bypass')
  })

  it('resolves dynamic engine profile paths', () => {
    expect(resolveRouteEngineId('/engines/wifi_attack_engine')).toBe('wifi_attack_engine')
    expect(resolveRouteEngineId('/engines/top-tier/jwt_attack')).toBe('jwt_attack')
    expect(resolveRouteEngineId('/engines/business/osint')).toBe('osint')
  })

  it('returns null for non-engine admin routes', () => {
    expect(resolveRouteEngineId('/billing')).toBeNull()
    expect(resolveRouteEngineId('/clients')).toBeNull()
    expect(resolveRouteEngineId('/agents')).toBeNull()
  })

  it('covers every static ROUTE_ENGINE_ID entry', () => {
    for (const [path, id] of Object.entries(ROUTE_ENGINE_ID)) {
      expect(resolveRouteEngineId(path)).toBe(id)
    }
  })
})
