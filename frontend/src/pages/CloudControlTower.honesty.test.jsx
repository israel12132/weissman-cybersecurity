import { describe, it, expect } from 'vitest'
import { readFileSync } from 'node:fs'
import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'

const src = readFileSync(
  join(dirname(fileURLToPath(import.meta.url)), 'CloudControlTower.jsx'),
  'utf8',
)

describe('CloudControlTower live-only truth', () => {
  it('does not paint an empty tenant picker when GET /api/clients fails', () => {
    expect(src).toMatch(/data-testid="cloud-control-tower-clients-unavailable"/)
    expect(src).toMatch(/clients_unavailable/)
    expect(src).toMatch(/setClientsUnavailable\(true\)/)
    expect(src).not.toMatch(/\.catch\(\(\) => \{\}\)/)
  })

  it('does not paint run_to_populate when GET /api/engines/history fails', () => {
    expect(src).toMatch(/data-testid="cloud-control-tower-history-unavailable"/)
    expect(src).toMatch(/history_unavailable/)
    expect(src).toMatch(/run\?\.unavailable/)
    expect(src).toMatch(/unavailable=\{historyUnavailable\}/)
  })

  it('does not dump leftover leftover-findings CSV after a failed history GET', () => {
    expect(src).toMatch(/const handleExportCsv = useCallback\(\(\) => \{\n {4}if \(historyUnavailable\) return/)
    expect(src).toMatch(/exportDisabled=\{historyUnavailable \|\| !filteredFindings\.length\}/)
  })

  it('mutes leftover leftover-GET Export CSV after a failed history GET', () => {
    expect(src).toMatch(/useEngineHistory\(activeTabDef\.engine\)/)
    expect(src).toMatch(/onExport=\{historyUnavailable \? undefined : handleExportCsv\}/)
    expect(src).toMatch(/onRefresh=\{handleRefresh\}/)
    expect(src).toMatch(/data-testid="cloud-control-tower-history-unavailable"/)
    expect(src).toMatch(/showToast\('error', d\.detail \|\| t\('pages\.cloudControlTower\.scan_failed'\)\)/)
    expect(src).toMatch(/showToast\('error', e\?\.message \?\? t\('pages\.cloudControlTower\.scan_failed'\)\)/)
    expect(src).not.toMatch(/setHistoryUnavailable/)
  })

})
