import { describe, it, expect } from 'vitest'
import { readFileSync } from 'node:fs'
import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'

const src = readFileSync(
  join(dirname(fileURLToPath(import.meta.url)), 'AIAnalysisEngine.jsx'),
  'utf8',
)

describe('AIAnalysisEngine live-only truth', () => {
  it('does not paint KPI zeros when findings load is unconfirmed', () => {
    expect(src).toMatch(/data-testid="ai-analysis-unavailable"/)
    expect(src).toMatch(/unavailable_title/)
    expect(src).toMatch(/const findingsList = Array\.isArray\(fd\) \? fd : Array\.isArray\(fd\?\.findings\) \? fd\.findings : null/)
    expect(src).toMatch(/if \(findingsList\) \{/)
    expect(src).toMatch(/!loading && !error && filtered\.length === 0/)
    expect(src).not.toMatch(/if \(fd\) \{\s*findingsOk = true/)
  })

  it('does not paint leftover leftover-last-updated after a failed intel GET', () => {
    expect(src).toMatch(/\{lastUpdated && !error && \(/)
    expect(src).toMatch(/\{!error && \(\n      <div className="rounded-xl border border-violet-500\/20/)
    expect(src).toMatch(/\{evidenceNotice\}/)
    expect(src).not.toMatch(/error \? t\('pages\.aiAnalysisEngine\.evidence_soc'\)/)
    expect(src).toMatch(/const handleExportCsv = useCallback\(\(\) => \{\n    if \(error\) return\n    exportPatternsCsv\(filtered\)/)
    expect(src).toMatch(/exportDisabled=\{\!\!error \|\| !filteredFindings\.length\}/)
  })

  it('mutes leftover leftover-GET Export CSV after a failed findings GET', () => {
    expect(src).toMatch(/apiFetch\('\/api\/findings\?limit=2000'\)/)
    expect(src).toMatch(/const handleExportCsv = useCallback\(\(\) => \{\n    if \(error\) return\n    exportPatternsCsv\(filtered\)/)
    expect(src).toMatch(/onExport=\{error \? undefined : handleExportCsv\}/)
    expect(src).toMatch(/exportDisabled=\{\!\!error \|\| !filteredFindings\.length\}/)
    expect(src).toMatch(/onRefresh=\{load\}/)
    expect(src).toMatch(/\} catch \(e\) \{\n      setError\(e\.message \|\| t\('pages\.aiAnalysisEngine\.load_error'\)\)/)
    expect(src).not.toMatch(/\} catch \(e\) \{\n      setError[\s\S]{0,160}setPatterns\(/)
  })
})
