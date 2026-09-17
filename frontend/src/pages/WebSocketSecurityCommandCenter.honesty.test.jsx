import { describe, it, expect } from 'vitest'
import { readFileSync } from 'node:fs'
import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'

const src = readFileSync(
  join(dirname(fileURLToPath(import.meta.url)), 'WebSocketSecurityCommandCenter.jsx'),
  'utf8',
)

describe('WebSocketSecurityCommandCenter live-only truth', () => {
  it('does not paint ready-to-scan when GET /api/engines/history fails', () => {
    expect(src).toMatch(/data-testid="websocket-security-history-unavailable"/)
    expect(src).toMatch(/history_unavailable/)
    expect(src).toMatch(/unavailable=\{historyUnavailable\}/)
    expect(src).toMatch(/!historyUnavailable/)
  })

  it('does not coerce missing posture to 100/A or paint leftover leftover-scorecards', () => {
    expect(src).toMatch(/detailFindings\.length > 0 && !historyUnavailable/)
    expect(src).toMatch(/const hasScore = raw != null && Number\.isFinite\(Number\(raw\)\)/)
    expect(src).not.toMatch(/\?\? 100/)
    expect(src).not.toMatch(/\?\? 'A'/)
  })

  it('does not dump leftover leftover-findings CSV after a failed history GET', () => {
    expect(src).toMatch(/const handleExportCsv = useCallback\(\(\) => \{\n {4}if \(historyUnavailable\) return/)
    expect(src).toMatch(/exportDisabled=\{historyUnavailable \|\| !filteredFindings\.length\}/)
  })

  it('mutes leftover leftover-GET Export CSV after a failed history GET', () => {
    expect(src).toMatch(/useWeissmanEnginePage\(ENGINE, detailFindings\)/)
    expect(src).toMatch(/onExport=\{historyUnavailable \? undefined : handleExportCsv\}/)
    expect(src).toMatch(/onRefresh=\{handleRefresh\}/)
    expect(src).toMatch(/data-testid="websocket-security-history-unavailable"/)
    expect(src).toMatch(/if \(!ok\) \{ setStatus\('error'\); showToast\('error', d\.detail \|\| t\('pages\.websocketSecurity\.scan_failed', 'Scan failed'\)\); return \}/)
    expect(src).toMatch(/setStatus\('error'\); showToast\('error', e\?\.message \?\? t\('pages\.websocketSecurity\.scan_failed', 'Scan failed'\)\)/)
    expect(src).not.toMatch(/setHistoryUnavailable/)
  })
})
