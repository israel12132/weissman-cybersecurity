import { describe, it, expect } from 'vitest'
import { readFileSync } from 'node:fs'
import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'

const src = readFileSync(
  join(dirname(fileURLToPath(import.meta.url)), 'MobileSecurity.jsx'),
  'utf8',
)

describe('MobileSecurity live-only truth', () => {
  it('does not paint zero apps when the mobile inventory is unconfirmed', () => {
    expect(src).toMatch(/data-testid="mobile-security-unavailable"/)
    expect(src).toMatch(/unavailable_title/)
    expect(src).toMatch(/setAppsUnavailable\(true\)/)
    expect(src).not.toMatch(/\.catch\(\(\) => setClients\(\[\]\)\)/)
  })

  it('does not paint never-run findings when GET /api/engines/history fails', () => {
    expect(src).toMatch(/data-testid="mobile-security-history-unavailable"/)
    expect(src).toMatch(/history_unavailable/)
    expect(src).toMatch(/unavailable=\{historyUnavailable\}/)
    expect(src).toMatch(/!historyUnavailable/)
  })

  it('does not paint leftover leftover-finding KPIs after a failed history GET', () => {
    expect(src).toMatch(/historyUnavailable \? '—' : findings\.length/)
    expect(src).toMatch(/!historyUnavailable && findings\.length > 0/)
  })
})
