import { describe, it, expect } from 'vitest'
import { readFileSync } from 'node:fs'
import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'

const src = readFileSync(
  join(dirname(fileURLToPath(import.meta.url)), 'DeceptionGridTab.jsx'),
  'utf8',
)

describe('DeceptionGridTab live-only truth', () => {
  it('does not paint an empty inventory when the deception store is down', () => {
    expect(src).not.toMatch(/catch \([^)]*\) \{\s*setAssets\(\[\]\)/)
    expect(src).toMatch(/setAssetsUnavailable\(true\)/)
    expect(src).toMatch(/data-testid="deception-grid-unavailable"/)
  })
})
