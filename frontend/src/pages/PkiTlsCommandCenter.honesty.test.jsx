import { describe, it, expect } from 'vitest'
import { readFileSync } from 'node:fs'
import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'

const src = readFileSync(
  join(dirname(fileURLToPath(import.meta.url)), 'PkiTlsCommandCenter.jsx'),
  'utf8',
)

describe('PkiTlsCommandCenter live-only truth', () => {
  it('does not paint run-to-populate when GET /api/engines/history fails', () => {
    expect(src).toMatch(/data-testid="pki-tls-history-unavailable"/)
    expect(src).toMatch(/history_unavailable/)
    expect(src).toMatch(/unavailable=\{historyUnavailable\}/)
    expect(src).toMatch(/!historyUnavailable/)
  })

  it('does not paint leftover leftover-scorecards after a failed history GET', () => {
    expect(src).toMatch(/findings\.length > 0 && !historyUnavailable && <Scorecard/)
    expect(src).toMatch(/detailFindings\.length > 0 && !historyUnavailable && <CategoryBreakdown/)
    expect(src).not.toMatch(/posture_score \?\? summary\.evidence\?\.posture_score \?\? 0/)
  })

  it('does not dump leftover leftover-findings CSV after a failed history GET', () => {
    expect(src).toMatch(/const handleExportCsv = useCallback\(\(\) => \{\n {4}if \(historyUnavailable\) return/)
    expect(src).toMatch(/exportDisabled=\{historyUnavailable \|\| !filteredFindings\.length\}/)
  })

  it('mutes leftover leftover-GET Export CSV after a failed history GET', () => {
    expect(src).toMatch(/useWeissmanEnginePage\(ENGINE, detailFindings\)/)
    expect(src).toMatch(/onExport=\{historyUnavailable \? undefined : handleExportCsv\}/)
    expect(src).toMatch(/onRefresh=\{handleRefresh\}/)
    expect(src).toMatch(/data-testid="pki-tls-history-unavailable"/)
    expect(src).toMatch(/if \(!ok\) \{ setStatus\('error'\); showToast\('error', d\.detail \|\| t\('pages\.pkiTlsPosture\.scan_failed', 'Scan failed'\)\); return \}/)
    expect(src).toMatch(/setStatus\('error'\); showToast\('error', e\?\.message \?\? t\('pages\.pkiTlsPosture\.scan_failed', 'Scan failed'\)\)/)
    expect(src).not.toMatch(/setHistoryUnavailable/)
  })
})
