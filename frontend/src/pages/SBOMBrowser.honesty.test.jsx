import { describe, it, expect } from 'vitest'
import { readFileSync } from 'node:fs'
import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'

const src = readFileSync(
  join(dirname(fileURLToPath(import.meta.url)), 'SBOMBrowser.jsx'),
  'utf8',
)

describe('SBOMBrowser live-only truth', () => {
  it('does not paint a clean SBOM when components fetch fails', () => {
    expect(src).toMatch(/data-testid="sbom-browser-unavailable"/)
    expect(src).toMatch(/unavailable_title/)
    expect(src).toMatch(/showUnavailable/)
    expect(src).toMatch(/!error && components\.length === 0/)
  })
})
