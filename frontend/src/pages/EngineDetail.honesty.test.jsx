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

  it('does not paint leftover leftover-finding counts after a failed history GET', () => {
    expect(src).toMatch(/historyUnavailable\s*\n\s*\? '—'\s*\n\s*: \(findings\.length \|\| \(lastHistoryRun\?\.findingsCount \?\? 0\)\)/)
    expect(src).toMatch(/historyUnavailable \? undefined : \(findings\.length > 0/)
    expect(src).toMatch(/historyUnavailable \? null : \(runHistory\.length > 0/)
    expect(src).toMatch(/historyUnavailable\s*\n\s*\? \(jobId \? `Job \$\{jobId\}` : undefined\)/)
    expect(src).toMatch(/run_history: historyUnavailable \? null : runHistory/)
  })

  it('does not dump leftover leftover-findings CSV after a failed history GET', () => {
    expect(src).toMatch(/const exportFindingsCsv = useCallback\(\(\) => \{\n {4}if \(historyUnavailable\) return/)
    expect(src).toMatch(/exportDisabled=\{historyUnavailable \|\| !findings\.length\}/)
  })

  it('mutes leftover leftover-GET Export CSV after a failed history GET', () => {
    expect(src).toMatch(/apiFetch\(`\/api\/engines\/history\/\$\{encodeURIComponent\(engineId\)\}\?limit=20`\)/)
    expect(src).toMatch(/onExport=\{historyUnavailable \? undefined : exportFindingsCsv\}/)
    expect(src).toMatch(/onRefresh=\{reloadHistory\}/)
    expect(src).toMatch(/data-testid="engine-detail-history-stat-unavailable"/)
    expect(src).toMatch(/showToast\('error', d\.detail \|\| d\.error \|\| `Scan failed \(\$\{status\}\)`\)/)
    expect(src).toMatch(/setHistoryUnavailable\(true\)/)
    expect(src).toMatch(/\{!historyUnavailable && \(/)
    expect(src).not.toMatch(/onExport=\{exportFindingsCsv\}/)
  })
})
