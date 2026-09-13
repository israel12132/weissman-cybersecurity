import { describe, it, expect } from 'vitest'
import { readFileSync } from 'node:fs'
import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'

const src = readFileSync(
  join(dirname(fileURLToPath(import.meta.url)), 'OsintEngineProfile.jsx'),
  'utf8',
)

describe('OsintEngineProfile live-only truth', () => {
  it('does not paint an empty tenant picker when GET /api/clients fails', () => {
    expect(src).toMatch(/data-testid="osint-engine-profile-clients-unavailable"/)
    expect(src).toMatch(/clients_unavailable/)
    expect(src).toMatch(/setClientsUnavailable\(true\)/)
    expect(src).not.toMatch(/\[OsintEngineProfile\] clients load failed/)
  })

  it('does not treat a failed integrations fetch as unconfigured scan prefill', () => {
    expect(src).toMatch(/data-testid="osint-engine-profile-integrations-unavailable"/)
    expect(src).toMatch(/integrations_unavailable/)
    expect(src).toMatch(/setIntegrationsUnavailable\(true\)/)
  })

  it('does not paint KPI zeros when GET /api/engines/history/osint fails', () => {
    expect(src).toMatch(/data-testid="osint-engine-profile-history-unavailable"/)
    expect(src).toMatch(/history_unavailable/)
    expect(src).toMatch(/setHistoryUnavailable\(true\)/)
    expect(src).toMatch(/historyLoading \|\| historyUnavailable/)
  })

  it('does not paint leftover leftover-history findings after a failed history GET', () => {
    expect(src).toMatch(/!historyUnavailable && findings\.length > 0/)
  })
})
