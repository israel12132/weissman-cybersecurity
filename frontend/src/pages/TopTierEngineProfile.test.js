import { describe, expect, it } from 'vitest'
import { readFileSync } from 'node:fs'
import { resolve } from 'node:path'

describe('TopTierEngineProfile imports', () => {
  it('imports TOP_TIER_PARAM_ROUTES', () => {
    const src = readFileSync(resolve(import.meta.dirname, 'TopTierEngineProfile.jsx'), 'utf8')
    expect(src).toMatch(/TOP_TIER_PARAM_ROUTES/)
    expect(src).toMatch(/from ['"]\.\.\/lib\/engineClientPrefill['"]/)
  })
})
