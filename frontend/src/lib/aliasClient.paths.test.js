import { describe, it, expect } from 'vitest'
import { withClientId } from './aliasClient.js'
describe('aliasClient paths', () => {
  it('existing query', () => expect(withClientId('/a?x=1', 2)).toContain('client_id=2'))
})