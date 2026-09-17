import { describe, it, expect } from 'vitest'
import { readFileSync } from 'node:fs'
import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'

const src = readFileSync(
  join(dirname(fileURLToPath(import.meta.url)), 'ClientIntegrations.jsx'),
  'utf8',
)

describe('ClientIntegrations live-only truth', () => {
  it('does not paint a blank integrations form as unconfigured when load fails', () => {
    expect(src).toMatch(/data-testid="client-integrations-unavailable"/)
    expect(src).toMatch(/unavailable_title/)
    expect(src).toMatch(/disabled=\{saving \|\| unavailable\}/)
  })

  it('does not dump leftover leftover-integrations JSON after a failed integrations GET', () => {
    expect(src).toMatch(/const handleExport = useCallback\(\(\) => \{\n {4}if \(integrationsGetFailed \|\| error \|\| unavailable\) return/)
    expect(src).toMatch(/exportDisabled=\{integrationsGetFailed \|\| !!error \|\| unavailable\}/)
    expect(src).toMatch(/if \(!hasLoadedRef\.current\) setUnavailable\(true\)/)
  })

  it('mutes leftover leftover-GET Export CSV after a failed integrations GET', () => {
    expect(src).toMatch(/apiFetch\(`\/api\/clients\/\$\{id\}\/integrations`\)/)
    expect(src).toMatch(/onExport=\{integrationsGetFailed \? undefined : handleExport\}/)
    expect(src).toMatch(/onRefresh=\{load\}/)
    expect(src).toMatch(/setIntegrationsGetFailed\(true\)/)
    expect(src).toMatch(/if \(!hasLoadedRef\.current\) setUnavailable\(true\)/)
    expect(src).toMatch(/method: 'PATCH'/)
    expect(src).not.toMatch(/Save failed[\s\S]{0,80}setIntegrationsGetFailed/)
  })

  it('mutes leftover leftover-GET readiness percent after a failed integrations GET', () => {
    expect(src).toMatch(/\{integrationsGetFailed \? '—' : `\$\{readiness\.percent\}%`\}/)
    expect(src).toMatch(/width: integrationsGetFailed \? '0%' : `\$\{readiness\.percent\}%`/)
    expect(src).toMatch(/setIntegrationsGetFailed\(true\)/)
    expect(src).not.toMatch(/Save failed[\s\S]{0,80}setIntegrationsGetFailed/)
  })
})
