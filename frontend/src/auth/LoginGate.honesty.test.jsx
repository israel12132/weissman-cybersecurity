import { describe, it, expect } from 'vitest'
import { readFileSync } from 'node:fs'
import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'

const src = readFileSync(
  join(dirname(fileURLToPath(import.meta.url)), 'LoginGate.jsx'),
  'utf8',
)

describe('LoginGate live-only truth', () => {
  it('does not interpolate a catalog fallback engine count into brand_story', () => {
    expect(src).not.toMatch(/PRODUCTION_ENGINE_COUNT/)
    expect(src).toMatch(/brand_story_checking/)
    expect(src).toMatch(/pulse\?\.production_engines/)
  })
})
