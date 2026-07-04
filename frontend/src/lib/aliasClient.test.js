import { describe, it, expect } from 'vitest'
import { withClientId } from './aliasClient.js'
describe('aliasClient', () => {
  it('query param', () => expect(withClientId('/a', 1)).toBe('/a?client_id=1'))
})