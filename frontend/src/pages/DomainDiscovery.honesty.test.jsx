import { describe, it, expect } from 'vitest'
import { readFileSync } from 'node:fs'
import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'

const src = readFileSync(
  join(dirname(fileURLToPath(import.meta.url)), 'DomainDiscovery.jsx'),
  'utf8',
)

describe('DomainDiscovery live-only truth', () => {
  it('does not paint an empty tenant picker when GET /api/clients fails', () => {
    expect(src).toMatch(/data-testid="domain-discovery-clients-unavailable"/)
    expect(src).toMatch(/clients_unavailable/)
    expect(src).toMatch(/setClientsUnavailable\(true\)/)
    expect(src).not.toMatch(/\.catch\(\(\) => \{\}\)/)
  })
})
