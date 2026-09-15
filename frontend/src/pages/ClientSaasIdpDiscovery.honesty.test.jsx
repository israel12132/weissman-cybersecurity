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

  it('mutes leftover client name in the title after a failed discovery GET', () => {
    expect(src).toMatch(/title=\{!error && clientName \? `\$\{t\('pages\.clientSaasIdpDiscovery\.title'\)\} — \$\{clientName\}` : t\('pages\.clientSaasIdpDiscovery\.title'\)\}/)
    expect(src).toMatch(/setError\(e\?\.message \|\| t\('pages\.clientSaasIdpDiscovery\.network_error'\)\)/)
    expect(src).not.toMatch(/catch \(e\) \{\s*setClientName\(''\)/)
    expect(src).not.toMatch(/catch \(e\) \{\s*setReport\(null\)/)
  })

  it('mutes leftover leftover-GET Export CSV after a failed discovery GET', () => {
    expect(src).toMatch(/apiFetch\(`\/api\/clients\/\$\{clientId\}\/discovery\/saas-idp`\)/)
    expect(src).toMatch(/const handleExportCsv = useCallback\(\(\) => \{\n    if \(error\) return/)
    expect(src).toMatch(/onExport=\{error \? undefined : handleExportCsv\}/)
    expect(src).toMatch(/exportDisabled=\{\!\!error \|\| !filteredFindings\.length\}/)
    expect(src).toMatch(/onRefresh=\{runDiscovery\}/)
    expect(src).not.toMatch(/catch \(e\) \{\s*setReport\(null\)/)
  })
})
