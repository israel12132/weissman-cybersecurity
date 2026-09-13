import { describe, it, expect } from 'vitest'
import { readFileSync } from 'node:fs'
import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'

const src = readFileSync(
  join(dirname(fileURLToPath(import.meta.url)), 'BusinessEngineProfile.jsx'),
  'utf8',
)

describe('BusinessEngineProfile live-only truth', () => {
  it('does not paint an empty tenant picker when GET /api/clients fails', () => {
    expect(src).toMatch(/data-testid="business-engine-profile-clients-unavailable"/)
    expect(src).toMatch(/clients_unavailable/)
    expect(src).toMatch(/setClientsUnavailable\(true\)/)
    expect(src).not.toMatch(/clients load failed — leave list unchanged/)
  })

  it('does not treat a failed integrations fetch as unconfigured scan prefill', () => {
    expect(src).toMatch(/data-testid="business-engine-profile-integrations-unavailable"/)
    expect(src).toMatch(/integrations_unavailable/)
    expect(src).toMatch(/setIntegrationsUnavailable\(true\)/)
    expect(src).not.toMatch(/apiFetch\(`\/api\/clients\/\$\{clientId\}\/integrations`\)\.catch\(\(\) => null\)/)
  })

  it('does not paint KPI zeros when GET /api/engines/history fails', () => {
    expect(src).toMatch(/data-testid="business-engine-profile-history-unavailable"/)
    expect(src).toMatch(/history_unavailable/)
    expect(src).toMatch(/setHistoryUnavailable\(true\)/)
    expect(src).toMatch(/profileLoading \|\| historyUnavailable/)
    expect(src).toMatch(/!historyUnavailable && !jobs\.length/)
    expect(src).toMatch(/!historyUnavailable && !findings\.length/)
  })

  it('does not paint leftover leftover-history charts or job rows after a failed history GET', () => {
    expect(src).toMatch(/!historyUnavailable &&[\s\S]{0,2000}LineChart accessibilityLayer data=\{findingsData\}/)
    expect(src).toMatch(/!historyUnavailable &&[\s\S]{0,800}BarChart accessibilityLayer data=\{statusData\}/)
    expect(src).toMatch(/!historyUnavailable && visibleJobs\.map/)
    expect(src).toMatch(/!historyUnavailable && visibleFindings\.map/)
    expect(src).toMatch(/if \(historyUnavailable\) \{[\s\S]{0,200}history_unavailable/)
  })

  it('does not dump leftover leftover-history JSON after a failed history GET', () => {
    expect(src).toMatch(/async function exportJson\(\) \{\n    if \(historyUnavailable\) return/)
    expect(src).toMatch(/exportDisabled=\{historyUnavailable\}/)
  })
})
