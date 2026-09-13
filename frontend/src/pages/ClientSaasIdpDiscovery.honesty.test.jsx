import { describe, it, expect } from 'vitest'
import { readFileSync } from 'node:fs'
import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'

const src = readFileSync(
  join(dirname(fileURLToPath(import.meta.url)), 'ClientSaasIdpDiscovery.jsx'),
  'utf8',
)

describe('ClientSaasIdpDiscovery live-only truth', () => {
  it('does not paint empty domains/IdP/SaaS when discovery load fails', () => {
    expect(src).toMatch(/data-testid="saas-idp-discovery-unavailable"/)
    expect(src).toMatch(/unavailable_title/)
    expect(src).toMatch(/error \? \(/)
  })

  it('does not dump leftover leftover-discovery CSV after a failed discovery GET', () => {
    expect(src).toMatch(/const handleExportCsv = useCallback\(\(\) => \{\n    if \(error\) return/)
    expect(src).toMatch(/exportDisabled=\{\!\!error \|\| !filteredFindings\.length\}/)
  })
})
