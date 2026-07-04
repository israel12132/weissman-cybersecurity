import { describe, it, expect } from 'vitest'
import { REALITY_KIND_META } from './realityKindMeta.js'
describe('realityKindMeta', () => {
  it('has live probe meta', () => expect(REALITY_KIND_META.real_probe).toBeTruthy())
})