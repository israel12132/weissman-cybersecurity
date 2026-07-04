import { describe, it, expect } from 'vitest'
import { resolveRouteEngineId, ROUTE_ENGINE_ID_PREFIX } from './routeEngineId.js'

describe('routeEngineId deep', () => {
  it('prefix list non-empty', () => {
    expect(ROUTE_ENGINE_ID_PREFIX.length).toBeGreaterThan(0)
  })

  it('resolves jwt lab', () => {
    expect(resolveRouteEngineId('/jwt-lab')).toBeTruthy()
  })

  it('resolves engine detail prefix', () => {
    expect(resolveRouteEngineId('/engines/jwt_attack')).toBe('jwt_attack')
  })
})
