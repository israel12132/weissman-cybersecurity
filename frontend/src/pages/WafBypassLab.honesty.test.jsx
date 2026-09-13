import { describe, it, expect } from 'vitest'
import { readFileSync } from 'node:fs'
import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'

const src = readFileSync(
  join(dirname(fileURLToPath(import.meta.url)), 'WafBypassLab.jsx'),
  'utf8',
)

describe('WafBypassLab live-only truth', () => {
  it('does not paint ready-to-scan when GET /api/engines/history fails', () => {
    expect(src).toMatch(/data-testid="waf-bypass-history-unavailable"/)
    expect(src).toMatch(/history_unavailable/)
    expect(src).toMatch(/unavailable=\{historyUnavailable\}/)
    expect(src).toMatch(/!historyUnavailable/)
    expect(src).not.toMatch(/scoreColor\(score \?\? 0\)/)
    expect(src).toMatch(/\(historyUnavailable \|\| score == null\) \? 'rgba\(255,255,255,0\.35\)' : scoreColor\(score\)/)
  })
})
