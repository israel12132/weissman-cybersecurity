import { describe, it, expect } from 'vitest'
import { resolveRouteEngineId, ROUTE_ENGINE_ID } from './routeEngineId.js'
describe('routeEngineId resolve', () => {
  it('proxy map', () => expect(ROUTE_ENGINE_ID['/engines/osint']).toBeTruthy())
  it('unknown path', () => expect(resolveRouteEngineId('/unknown')).toBeFalsy())
})