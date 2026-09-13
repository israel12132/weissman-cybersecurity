import { describe, it, expect } from 'vitest'
import { readFileSync } from 'node:fs'
import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'

const src = readFileSync(
  join(dirname(fileURLToPath(import.meta.url)), 'ExecutiveOverview.jsx'),
  'utf8',
)

describe('ExecutiveOverview live-only truth', () => {
  it('does not paint no_snapshot when financial-risk or attack-paths GETs fail', () => {
    expect(src).toMatch(/data-testid="executive-overview-financial-unavailable"/)
    expect(src).toMatch(/data-testid="executive-overview-attack-unavailable"/)
    expect(src).toMatch(/financial_unavailable/)
    expect(src).toMatch(/attack_unavailable/)
    expect(src).toMatch(/Promise\.allSettled/)
    expect(src).not.toMatch(/financial-risk\/\$\{encodeURIComponent\(cid\)\}`\)\.catch\(\(\) => null\)/)
    expect(src).not.toMatch(/attack-paths\/\$\{encodeURIComponent\(cid\)\}`\)\.catch\(\(\) => null\)/)
  })

  it('does not paint 0-tactics / 0-EPSS-rows / 0-UEBA as empty-clean when those GETs fail', () => {
    expect(src).toMatch(/global\.coverage \? t\(`\$\{NS\}\.coverage_sub`, \{ tactics: totals\.tactics_covered \?\? 0 \}\) : t\(`\$\{NS\}\.na`\)/)
    expect(src).toMatch(/epss\?\.rows != null \? epss\.rows : '—'/)
    expect(src).not.toMatch(/epss\?\.rows \?\? 0/)
    expect(src).toMatch(/uebaList \? t\(`\$\{NS\}\.ueba_sub`, \{ total: uebaList\.length \}\) : t\(`\$\{NS\}\.na`\)/)
    expect(src).not.toMatch(/uebaList \? uebaList\.length : 0/)
  })
})
