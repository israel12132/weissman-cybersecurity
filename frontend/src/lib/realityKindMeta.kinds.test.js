import { describe, it, expect } from 'vitest'
import { REALITY_KIND_META } from './realityKindMeta.js'
describe('realityKindMeta kinds', () => {
  for (const k of ['real_probe', 'alias', 'agent_required']) {
    it(`has ${k}`, () => expect(REALITY_KIND_META[k]).toBeTruthy())
  }
})