import { describe, it, expect } from 'vitest'
import { readFileSync } from 'node:fs'
import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'

const src = readFileSync(
  join(dirname(fileURLToPath(import.meta.url)), 'EngineDetail.jsx'),
  'utf8',
)

describe('EngineDetail live-only truth', () => {
  it('does not paint an empty tenant picker when GET /api/clients fails', () => {
    expect(src).toMatch(/data-testid="engine-detail-clients-unavailable"/)
    expect(src).toMatch(/clients_unavailable/)
    expect(src).toMatch(/setClientsUnavailable\(true\)/)
    expect(src).not.toMatch(/\.then\(\(d\) => \{ if \(Array\.isArray\(d\)\) setClients\(d\) \}\)/)
  })

  it('does not treat a failed integrations fetch as unconfigured scan prefill', () => {
    expect(src).toMatch(/data-testid="engine-detail-integrations-unavailable"/)
    expect(src).toMatch(/integrations_unavailable/)
    expect(src).toMatch(/setIntegrationsUnavailable\(true\)/)
    expect(src).not.toMatch(/\.catch\(\(\) => \{ if \(!cancelled\) setClientIntegrations\(null\) \}\)/)
  })

  it('does not paint never-run when GET /api/engines/history fails', () => {
    expect(src).toMatch(/data-testid="engine-detail-history-unavailable"/)
    expect(src).toMatch(/history_unavailable/)
    expect(src).toMatch(/setHistoryUnavailable\(true\)/)
    expect(src).not.toMatch(/fall through to localStorage/)
  })
})
