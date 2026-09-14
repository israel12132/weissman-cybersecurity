import { describe, it, expect } from 'vitest'
import { readFileSync } from 'node:fs'
import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'

const src = readFileSync(
  join(dirname(fileURLToPath(import.meta.url)), 'TopTierEngineProfile.jsx'),
  'utf8',
)

describe('TopTierEngineProfile live-only truth', () => {
  it('does not paint an empty tenant picker when GET /api/clients fails', () => {
    expect(src).toMatch(/data-testid="top-tier-engine-profile-clients-unavailable"/)
    expect(src).toMatch(/clients_unavailable/)
    expect(src).toMatch(/setClientsUnavailable\(true\)/)
    expect(src).not.toMatch(/apiFetch\('\/api\/clients'\)\.catch\(\(\) => null\)/)
  })

  it('does not treat a failed integrations fetch as unconfigured scan prefill', () => {
    expect(src).toMatch(/data-testid="top-tier-engine-profile-integrations-unavailable"/)
    expect(src).toMatch(/integrations_unavailable/)
    expect(src).toMatch(/setIntegrationsUnavailable\(true\)/)
    expect(src).not.toMatch(/apiFetch\(`\/api\/clients\/\$\{clientId\}\/integrations`\)\.catch\(\(\) => null\)/)
  })

  it('does not paint empty_jobs when top-tier history cannot be confirmed', () => {
    expect(src).toMatch(/data-testid="top-tier-engine-profile-history-unavailable"/)
    expect(src).toMatch(/history_unavailable/)
    expect(src).toMatch(/setHistoryUnavailable\(true\)/)
    expect(src).not.toMatch(/if \(historyRes\.status === 'fulfilled'\) \{\s*setHistory\(/)
  })

  it('does not paint leftover leftover-history charts after a failed top-tier history GET', () => {
    expect(src).toMatch(/!historyUnavailable &&[\s\S]{0,800}BarChart accessibilityLayer data=\{statusChartData\}/)
    expect(src).toMatch(/!historyUnavailable &&[\s\S]{0,2000}LineChart accessibilityLayer data=\{findingsTrendData\}/)
    expect(src).toMatch(/!historyUnavailable && jobs\.length > 0/)
    expect(src).toMatch(/data-testid="top-tier-engine-profile-history-unavailable"/)
    expect(src).toMatch(/if \(auditUnavailable\) \{[\s\S]{0,200}audit_unavailable/)
  })

  it('does not dump leftover leftover-history JSON after a failed history GET', () => {
    expect(src).toMatch(/async function exportJson\(\) \{\n    if \(historyUnavailable\) return/)
    expect(src).toMatch(/exportDisabled=\{historyUnavailable\}/)
  })

  it('mutes leftover leftover-GET Export PDF after a failed history GET', () => {
    expect(src).toMatch(/apiFetch\(`\/api\/engines\/top-tier\/\$\{encodeURIComponent\(engineId\)\}\/history\?limit=80`\)/)
    expect(src).toMatch(/function exportPdf\(\) \{\n    if \(historyUnavailable\) return/)
    expect(src).toMatch(/\{!historyUnavailable && \(\s*<Button variant="unstyled"\s*type="button"\s*onClick=\{exportPdf\}/)
    expect(src).toMatch(/pages\.topTierEngineProfile\.export_pdf/)
    expect(src).toMatch(/setHistoryUnavailable\(true\)/)
    expect(src).not.toMatch(/catch \{\s*setHistoryUnavailable\(true\)\s*setHistory\(/)
    expect(src).not.toMatch(/setHistoryUnavailable\(true\)\s*setHistory\(/)
  })
})
