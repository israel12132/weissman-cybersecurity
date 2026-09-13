import { describe, it, expect } from 'vitest'
import { readFileSync } from 'node:fs'
import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'

const src = readFileSync(
  join(dirname(fileURLToPath(import.meta.url)), 'NetworkProtocols.jsx'),
  'utf8',
)

describe('NetworkProtocols live-only truth', () => {
  it('does not paint protocol KPI zeros when the SOC payload is unconfirmed', () => {
    expect(src).toMatch(/data-testid="network-protocols-unavailable"/)
    expect(src).toMatch(/unavailable_title/)
    expect(src).toMatch(/setClientsUnavailable\(true\)/)
    expect(src).not.toMatch(/apiFetch\('\/api\/clients'\)[\s\S]{0,180}\.catch\(\(\) => \{\}\)/)
  })
})
