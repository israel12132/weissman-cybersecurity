import { describe, it, expect } from 'vitest'
import { readFileSync } from 'node:fs'
import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'

const src = readFileSync(
  join(dirname(fileURLToPath(import.meta.url)), 'CicdPipelineSecurityCommandCenter.jsx'),
  'utf8',
)

describe('CicdPipelineSecurityCommandCenter live-only truth', () => {
  it('does not paint run-to-populate when GET /api/engines/history fails', () => {
    expect(src).toMatch(/data-testid="cicd-pipeline-history-unavailable"/)
    expect(src).toMatch(/history_unavailable/)
    expect(src).toMatch(/unavailable=\{historyUnavailable\}/)
    expect(src).toMatch(/!historyUnavailable/)
  })

  it('does not paint a lime-0 exposure ring when the posture score is unconfirmed', () => {
    expect(src).toMatch(/const hasScore = score != null && Number\.isFinite\(Number\(score\)\)/)
    expect(src).not.toMatch(/const pct = Math\.min\(100, Math\.max\(0, score \?\? 0\)\)/)
    expect(src).toMatch(/const liveMetrics = historyUnavailable \? null : metrics/)
    expect(src).toMatch(/liveMetrics \? \(liveMetrics\.platforms\?\.length \?\? 0\) : '—'/)
    expect(src).toMatch(/liveMetrics \? attackPaths\.length : '—'/)
    expect(src).not.toMatch(/attackPaths\.length \|\| '—'/)
    expect(src).toMatch(/!historyUnavailable && attackPaths\.length > 0/)
  })

  it('does not dump leftover leftover-findings CSV after a failed history GET', () => {
    expect(src).toMatch(/const handleExportCsv = useCallback\(\(\) => \{\n    if \(historyUnavailable\) return/)
    expect(src).toMatch(/exportDisabled=\{historyUnavailable \|\| !filteredFindings\.length\}/)
  })

  it('mutes leftover leftover-GET Export CSV after a failed history GET', () => {
    expect(src).toMatch(/useWeissmanEnginePage\(ENGINE_ID, realFindings\)/)
    expect(src).toMatch(/onExport=\{historyUnavailable \? undefined : handleExportCsv\}/)
    expect(src).toMatch(/onRefresh=\{handleRefresh\}/)
    expect(src).toMatch(/data-testid="cicd-pipeline-history-unavailable"/)
    expect(src).toMatch(/appendLine\(`\[ERROR\] \$\{data\.detail \|\| 'Scan failed'\}`\)/)
    expect(src).toMatch(/appendLine\(`\[ERROR\] \$\{e\.message\}`\)/)
    expect(src).not.toMatch(/setHistoryUnavailable/)
  })

})
