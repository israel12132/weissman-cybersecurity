import { describe, it, expect } from 'vitest'
import { readFileSync } from 'node:fs'
import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'

const src = readFileSync(
  join(dirname(fileURLToPath(import.meta.url)), 'DarkWebMonitor.jsx'),
  'utf8',
)

describe('DarkWebMonitor live-only truth', () => {
  it('does not paint zero dark-web hits when findings fetch fails', () => {
    expect(src).toMatch(/data-testid="dark-web-unavailable"/)
    expect(src).toMatch(/unavailable_title/)
    expect(src).not.toMatch(/setFindings\(\[\]\)/)
  })

  it('does not paint leftover leftover-last-updated after a failed findings GET', () => {
    expect(src).toMatch(/\{lastRefresh && !error && \(/)
  })
})
