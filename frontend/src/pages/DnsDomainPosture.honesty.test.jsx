import { describe, it, expect } from 'vitest'
import { readFileSync } from 'node:fs'
import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'

const src = readFileSync(
  join(dirname(fileURLToPath(import.meta.url)), 'DnsDomainPosture.jsx'),
  'utf8',
)

describe('DnsDomainPosture live-only truth', () => {
  it('does not paint appears-strong when GET /api/engines/history fails', () => {
    expect(src).toMatch(/data-testid="dns-domain-posture-history-unavailable"/)
    expect(src).toMatch(/history_unavailable/)
    expect(src).toMatch(/unavailable=\{historyUnavailable\}/)
    expect(src).toMatch(/!historyUnavailable/)
  })

  it('does not coerce missing hijack-resistance to 0 or paint leftover leftover-scorecards', () => {
    expect(src).toMatch(/!historyUnavailable && <Scorecard/)
    expect(src).toMatch(/const hasScore = raw != null && Number\.isFinite\(Number\(raw\)\)/)
    expect(src).not.toMatch(/hijack_resistance_score \?\? summary\.posture_score \?\? 0/)
  })

  it('does not dump leftover leftover-findings CSV after a failed history GET', () => {
    expect(src).toMatch(/const handleExportCsv = useCallback\(\(\) => \{\n {4}if \(historyUnavailable\) return/)
    expect(src).toMatch(/exportDisabled=\{historyUnavailable \|\| !filteredFindings\.length\}/)
  })

  it('mutes leftover leftover-GET Export CSV after a failed history GET', () => {
    expect(src).toMatch(/useWeissmanEnginePage\(ENGINE, issues\)/)
    expect(src).toMatch(/onExport=\{historyUnavailable \? undefined : handleExportCsv\}/)
    expect(src).toMatch(/onRefresh=\{handleRefresh\}/)
    expect(src).toMatch(/data-testid="dns-domain-posture-history-unavailable"/)
    expect(src).toMatch(/showToast\('error', d\.detail \|\| t\('pages\.dnsDomainPosture\.scan_failed', 'Scan failed'\)\)/)
    expect(src).toMatch(/showToast\('error', e\?\.message \?\? t\('pages\.dnsDomainPosture\.scan_failed', 'Scan failed'\)\)/)
    expect(src).not.toMatch(/setHistoryUnavailable/)
  })

})
