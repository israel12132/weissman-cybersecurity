import { describe, it, expect } from 'vitest'
import { readFileSync } from 'node:fs'
import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'

const src = readFileSync(
  join(dirname(fileURLToPath(import.meta.url)), 'CeoGenesisPanel.jsx'),
  'utf8',
)

describe('CeoGenesisPanel live-only truth', () => {
  it('mutes leftover leftover-hpc policy after a failed HPC GET', () => {
    expect(src).toMatch(/\{eff && !hpcErr && \(/)
    expect(src).toMatch(/\{!hpcErr && \(/)
    expect(src).toMatch(/\{!strategyErr && \(/)
    expect(src).toMatch(/catch \(err\) \{\n {6}setHpcErr\(err\.message \|\| t\('components\.ceo\.genesisPanel\.loadFailed'\)\)\n {4}\}/)
    expect(src).not.toMatch(/catch \(err\) \{\s*setHpcErr\([^)]+\)\s*setHpcView\(null\)/)
    expect(src).not.toMatch(/catch \(err\) \{\s*setHpcErr\([^)]+\)\s*setResearchPct\(/)
  })
})
