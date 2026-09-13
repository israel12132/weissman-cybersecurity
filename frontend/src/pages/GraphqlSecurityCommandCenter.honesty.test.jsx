import { describe, it, expect } from 'vitest'
import { readFileSync } from 'node:fs'
import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'

const src = readFileSync(
  join(dirname(fileURLToPath(import.meta.url)), 'GraphqlSecurityCommandCenter.jsx'),
  'utf8',
)

describe('GraphqlSecurityCommandCenter live-only truth', () => {
  it('does not paint an empty tenant picker when GET /api/clients fails', () => {
    expect(src).toMatch(/data-testid="graphql-security-clients-unavailable"/)
    expect(src).toMatch(/clients_unavailable/)
    expect(src).toMatch(/setClientsUnavailable\(true\)/)
    expect(src).toMatch(/Array\.isArray\(d\?\.clients\)/)
    expect(src).not.toMatch(/\.then\(\(d\) => \{ if \(Array\.isArray\(d\)\) setClients\(d\) \}\)/)
  })
})
