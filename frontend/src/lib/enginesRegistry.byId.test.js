import { describe, it, expect } from 'vitest'
import { ENGINES_BY_ID } from './enginesRegistry.js'
describe('ENGINES_BY_ID', () => {
  it('indexed', () => expect(ENGINES_BY_ID.osint?.id).toBe('osint'))
})