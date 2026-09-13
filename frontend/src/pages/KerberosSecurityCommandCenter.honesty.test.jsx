import { describe, it, expect } from 'vitest'
import { readFileSync } from 'node:fs'
import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'

const src = readFileSync(
  join(dirname(fileURLToPath(import.meta.url)), 'KerberosSecurityCommandCenter.jsx'),
  'utf8',
)

describe('KerberosSecurityCommandCenter live-only truth', () => {
  it('does not paint runToPopulate when GET /api/engines/history fails', () => {
    expect(src).toMatch(/data-testid="kerberos-security-history-unavailable"/)
    expect(src).toMatch(/historyUnavailable/)
    expect(src).toMatch(/unavailable=\{historyUnavailable\}/)
    expect(src).toMatch(/!historyUnavailable/)
  })

  it('does not paint leftover leftover-posture after a failed history GET', () => {
    expect(src).toMatch(/posture && !historyUnavailable/)
    expect(src).toMatch(/!historyUnavailable && paths\.length > 0/)
    expect(src).toMatch(/const hasScore = score != null && Number\.isFinite\(Number\(score\)\)/)
  })
})
