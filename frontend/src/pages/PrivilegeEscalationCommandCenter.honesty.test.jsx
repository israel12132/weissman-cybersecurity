import { describe, it, expect } from 'vitest'
import { readFileSync } from 'node:fs'
import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'

const src = readFileSync(
  join(dirname(fileURLToPath(import.meta.url)), 'PrivilegeEscalationCommandCenter.jsx'),
  'utf8',
)

describe('PrivilegeEscalationCommandCenter live-only truth', () => {
  it('does not paint runToPopulate when GET /api/engines/history fails', () => {
    expect(src).toMatch(/data-testid="privilege-escalation-history-unavailable"/)
    expect(src).toMatch(/historyUnavailable/)
    expect(src).toMatch(/unavailable=\{historyUnavailable\}/)
    expect(src).toMatch(/!historyUnavailable/)
  })

  it('does not paint leftover leftover-posture above the unavailable banner', () => {
    expect(src).toMatch(/posture && !historyUnavailable/)
    expect(src).not.toMatch(/ev\.score \?\? 0/)
    expect(src).not.toMatch(/ds\.score \?\? 0/)
    expect(src).not.toMatch(/n \?\? 0/)
    expect(src).toMatch(/if \(historyUnavailable\) return/)
    expect(src).toMatch(/!historyUnavailable && findings\.length > 0/)
  })

  it('does not dump leftover leftover-findings CSV after a failed history GET', () => {
    expect(src).toMatch(/const handleExportCsv = useCallback\(\(\) => \{\n    if \(historyUnavailable\) return/)
    expect(src).toMatch(/exportDisabled=\{historyUnavailable \|\| !filteredFindings\.length\}/)
  })

  it('mutes leftover leftover-GET Export CSV after a failed history GET', () => {
    expect(src).toMatch(/useWeissmanEnginePage\(ENGINE_ID, regular\)/)
    expect(src).toMatch(/onExport=\{historyUnavailable \? undefined : handleExportCsv\}/)
    expect(src).toMatch(/onRefresh=\{handleRefresh\}/)
    expect(src).toMatch(/data-testid="privilege-escalation-history-unavailable"/)
    expect(src).toMatch(/if \(!ok\) \{ setStatus\('error'\); showToastMsg\('error', d\.detail \|\| L\.scanFailed\); return \}/)
    expect(src).toMatch(/showToastMsg\('error', e\?\.message \?\? L\.scanFailed\)/)
    expect(src).not.toMatch(/setHistoryUnavailable/)
  })
})
