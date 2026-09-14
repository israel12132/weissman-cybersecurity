import { describe, it, expect } from 'vitest'
import { readFileSync } from 'node:fs'
import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'

const here = dirname(fileURLToPath(import.meta.url))
const bar = readFileSync(join(here, 'EngineIntegrationsBar.jsx'), 'utf8')
const hook = readFileSync(join(here, '../../hooks/useClientIntegrations.js'), 'utf8')
const ctx = readFileSync(join(here, '../../context/ClientContext.jsx'), 'utf8')

describe('EngineIntegrationsBar live-only truth', () => {
  it('does not paint unconfirmed 0% after leftover leftover-GET integrations fail', () => {
    expect(bar).toMatch(/\{integrationsUnavailable \? '—' : integrationsLoading \? '…' : `\$\{pct\}%`\}/)
    expect(bar).toMatch(/width: integrationsUnavailable \? '0%' : `\$\{pct\}%`/)
    expect(bar).toMatch(/data-testid="engine-integrations-unavailable"/)
    expect(bar).toMatch(/!integrationsUnavailable && readiness\.chips\.map/)
    expect(bar).not.toMatch(/\{integrationsLoading \? '…' : `\$\{pct\}%`\}/)
  })

  it('latches GET-only unavailable on leftover leftover-GET catch-clear without dropping catch-clear', () => {
    expect(hook).toMatch(/fetchClientIntegrations\(clientId\)/)
    expect(hook).toMatch(/setLocalIntegrations\(null\)\n          setLocalUnavailable\(true\)/)
    expect(ctx).toMatch(/apiFetch\(`\/api\/clients\/\$\{clientId\}\/integrations`\)/)
    expect(ctx).toMatch(/setClientIntegrations\(null\)\n        setIntegrationsUnavailable\(true\)/)
    expect(ctx).toMatch(/integrationsUnavailable,/)
  })

  it('latches unavailable when hub leftover leftover-GET resolves null without throw', () => {
    expect(hook).toMatch(/if \(d == null\) \{\n            setLocalIntegrations\(null\)\n            setLocalUnavailable\(true\)/)
    expect(hook).not.toMatch(/\.then\(\(d\) => \{\n        if \(!cancelled\) \{\n          setLocalIntegrations\(d\)\n          setLocalUnavailable\(false\)/)
  })
})
