import { describe, it, expect } from 'vitest'
import { readFileSync } from 'node:fs'
import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'

const src = readFileSync(
  join(dirname(fileURLToPath(import.meta.url)), 'DnsDomainPosture.jsx'),
  'utf8',
)

describe('DnsDomainPosture live-only truth', () => {
  it('does not paint appears-strong when GET /api/engines/history fails', () => {
    expect(src).toMatch(/data-testid="dns-domain-posture-history-unavailable"/)
    expect(src).toMatch(/history_unavailable/)
    expect(src).toMatch(/unavailable=\{historyUnavailable\}/)
    expect(src).toMatch(/!historyUnavailable/)
  })
})
