import { describe, it, expect } from 'vitest'
import { readFileSync } from 'node:fs'
import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'

const src = readFileSync(
  join(dirname(fileURLToPath(import.meta.url)), 'MitreCoverageHeatmap.jsx'),
  'utf8',
)

describe('MitreCoverageHeatmap live-only truth', () => {
  it('does not paint leftover MITRE cells or leftover summary counts after a failed exec-kpis poll', () => {
    expect(src).toMatch(/err \? '—' : t\(`\$\{NS\}\.summary`, \{ techniques: totalTechniques, hits: totalHits \}\)/)
    expect(src).toMatch(/\{\!err && \(/)
    expect(src).toMatch(/data-testid="mitre-heatmap-unavailable"/)
    expect(src).toMatch(/if \(!cancelled\) setErr\(e\?\.message \|\| 'fetch failed'\)/)
    expect(src).not.toMatch(/setData\(null\)/)
  })
})
