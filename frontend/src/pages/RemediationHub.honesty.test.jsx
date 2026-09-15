import { describe, it, expect } from 'vitest'
import { readFileSync } from 'node:fs'
import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'

const src = readFileSync(
  join(dirname(fileURLToPath(import.meta.url)), 'RemediationHub.jsx'),
  'utf8',
)

describe('RemediationHub live-only truth', () => {
  it('does not paint pending-fix zeros when findings fetch fails', () => {
    expect(src).toMatch(/data-testid="remediation-hub-unavailable"/)
    expect(src).toMatch(/unavailable_title/)
    expect(src).toMatch(/loading=\{loading \|\| !!error\}/)
    expect(src).toMatch(/ok\.length !== list\.length/)
  })

  it('does not dump leftover leftover-families after a failed findings GET', () => {
    expect(src).toMatch(/families_heading', \{ count: error \? '—' : workflows\.length \}/)
    expect(src).toMatch(/const handleExportCsv = useCallback\(\(\) => \{\n    if \(error\) return/)
    expect(src).toMatch(/exportDisabled=\{\!\!error \|\| !filteredFindings\.length\}/)
    expect(src).toMatch(/healStats && !error && \(/)
  })

  it('mutes leftover leftover-fix drawer after a failed findings GET', () => {
    expect(src).toMatch(/\{selectedFinding && !error && \(\n        <RemediationDetail finding=\{selectedFinding\}/)
    expect(src).toMatch(/setError\(e\.message \|\| 'Failed to load findings'\)/)
    expect(src).not.toMatch(/catch \(e\) \{\s*setSelectedFinding\(null\)/)
    expect(src).not.toMatch(/catch \(e\) \{\s*setFindings\(\[\]\)/)
  })

  it('mutes leftover leftover-GET Export CSV after a failed findings GET', () => {
    expect(src).toMatch(/apiFetch\('\/api\/findings\?limit=2000'\)/)
    expect(src).toMatch(/const handleExportCsv = useCallback\(\(\) => \{\n    if \(error\) return/)
    expect(src).toMatch(/onExport=\{error \? undefined : handleExportCsv\}/)
    expect(src).toMatch(/exportDisabled=\{\!\!error \|\| !filteredFindings\.length\}/)
    expect(src).toMatch(/setError\(e\.message \|\| 'Failed to load findings'\)/)
    expect(src).not.toMatch(/catch \(e\) \{\s*setFindings\(\[\]\)/)
  })
})
