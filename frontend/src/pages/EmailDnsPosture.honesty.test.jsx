import { describe, it, expect } from 'vitest'
import { readFileSync } from 'node:fs'
import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'

const src = readFileSync(
  join(dirname(fileURLToPath(import.meta.url)), 'EmailDnsPosture.jsx'),
  'utf8',
)

describe('EmailDnsPosture live-only truth', () => {
  it('does not paint appears-strong when GET /api/engines/history fails', () => {
    expect(src).toMatch(/data-testid="email-dns-history-unavailable"/)
    expect(src).toMatch(/history_unavailable/)
    expect(src).toMatch(/historyUnavailable/)
    expect(src).toMatch(/!historyUnavailable/)
  })

  it('does not coerce missing axes to 0-clean or paint leftover leftover-scorecards', () => {
    expect(src).toMatch(/!historyUnavailable && <Scorecard/)
    expect(src).toMatch(/const hasScore = raw != null && Number\.isFinite\(Number\(raw\)\)/)
    expect(src).not.toMatch(/summary\.score \?\? 0/)
    expect(src).not.toMatch(/Number\(value\) \|\| 0/)
  })

  it('does not dump leftover leftover-findings CSV after a failed history GET', () => {
    expect(src).toMatch(/const handleExportCsv = useCallback\(\(\) => \{\n    if \(historyUnavailable\) return/)
    expect(src).toMatch(/exportDisabled=\{historyUnavailable \|\| !filteredFindings\.length\}/)
  })

  it('mutes leftover leftover-GET Export CSV after a failed history GET', () => {
    expect(src).toMatch(/useWeissmanEnginePage\(ENGINE, issues\)/)
    expect(src).toMatch(/onExport=\{historyUnavailable \? undefined : handleExportCsv\}/)
    expect(src).toMatch(/onRefresh=\{handleRefresh\}/)
    expect(src).toMatch(/data-testid="email-dns-history-unavailable"/)
    expect(src).toMatch(/if \(!ok\) \{ setStatus\('error'\); showToast\('error', d\.detail \|\| t\('pages\.emailDnsPosture\.toast_scan_failed'\)\); return \}/)
    expect(src).toMatch(/setStatus\('error'\); showToast\('error', e\?\.message \?\? t\('pages\.emailDnsPosture\.toast_scan_failed'\)\)/)
    expect(src).not.toMatch(/setHistoryUnavailable/)
  })

})
