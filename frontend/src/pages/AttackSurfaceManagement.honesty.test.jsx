import { describe, it, expect } from 'vitest'
import { readFileSync } from 'node:fs'
import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'

const src = readFileSync(
  join(dirname(fileURLToPath(import.meta.url)), 'AttackSurfaceManagement.jsx'),
  'utf8',
)

describe('AttackSurfaceManagement live-only truth', () => {
  it('does not paint ready-to-map when GET /api/engines/history fails', () => {
    expect(src).toMatch(/data-testid="attack-surface-history-unavailable"/)
    expect(src).toMatch(/history_unavailable/)
    expect(src).toMatch(/unavailable=\{historyUnavailable\}/)
    expect(src).toMatch(/!historyUnavailable/)
  })

  it('does not paint leftover leftover-hero after a failed history GET', () => {
    expect(src).toMatch(/report && !historyUnavailable &&/)
  })

  it('does not dump leftover leftover-findings CSV after a failed history GET', () => {
    expect(src).toMatch(/const handleExportCsv = useCallback\(\(\) => \{\n {4}if \(historyUnavailable\) return/)
    expect(src).toMatch(/exportDisabled=\{historyUnavailable \|\| !assetFilteredFindings\.length\}/)
  })

  it('does not dump leftover leftover-surface JSON after a failed history GET', () => {
    expect(src).toMatch(/const handleExport = useCallback\(\(\) => \{\n {4}if \(historyUnavailable\) return/)
  })

  it('mutes leftover leftover-GET Export CSV after a failed history GET', () => {
    expect(src).toMatch(/useWeissmanEnginePage\(ENGINE, issues\)/)
    expect(src).toMatch(/onExport=\{historyUnavailable \? undefined : handleExportCsv\}/)
    expect(src).toMatch(/onRefresh=\{handleRefresh\}/)
    expect(src).toMatch(/data-testid="attack-surface-history-unavailable"/)
    expect(src).toMatch(/showToast\('error', d\.detail \|\| d\.error \|\| t\('pages\.attackSurfaceManagement\.toast_scan_failed', \{ status \}\)\)/)
    expect(src).toMatch(/showToast\('error', e\?\.message \?\? t\('pages\.attackSurfaceManagement\.toast_network_error'\)\)/)
    expect(src).not.toMatch(/setHistoryUnavailable/)
  })
})
