import { describe, it, expect } from 'vitest'
import { resolveRouteEngineId } from './routeEngineId.js'
describe('routeEngineId extra', () => {
  it('osint route', () => expect(resolveRouteEngineId('/engines/osint')).toBeTruthy())
})