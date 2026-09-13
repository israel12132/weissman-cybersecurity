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
})
