import { describe, it, expect } from 'vitest'
import { readFileSync } from 'node:fs'
import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'

const src = readFileSync(
  join(dirname(fileURLToPath(import.meta.url)), 'AlertRulesEngine.jsx'),
  'utf8',
)

describe('AlertRulesEngine live-only truth', () => {
  it('does not paint alert-rule KPI zeros when GET /api/alerts/rules is unconfirmed', () => {
    expect(src).toMatch(/data-testid="alert-rules-unavailable"/)
    expect(src).toMatch(/unavailable_title/)
    expect(src).toMatch(/unavailable \? \(/)
  })

  it('does not paint leftover leftover-rule counts after a failed rules GET', () => {
    expect(src).toMatch(/count: unavailable \? '—' : filteredRules\.length/)
    expect(src).toMatch(/resultCount=\{unavailable \? undefined : visibleRules\.length\}/)
    expect(src).toMatch(/const handleExportCsv = useCallback\(\(\) => \{\n    if \(unavailable\) return/)
    expect(src).toMatch(/exportDisabled=\{unavailable \|\| !filteredFindings\.length\}/)
  })

  it('mutes leftover leftover-edit rule modal after a failed rules GET', () => {
    expect(src).toMatch(/\{\(createModal \|\| \(editModal && !unavailable\)\) && \(/)
    expect(src).toMatch(/setUnavailable\(true\);\n      toast\.error\(t\('pages\.alertRulesEngine\.load_failed'\)\)/)
    expect(src).not.toMatch(/setUnavailable\(true\);\n      setEditModal/)
  })

  it('mutes leftover leftover-GET Export CSV after a failed rules GET', () => {
    expect(src).toMatch(/api\.get\('\/api\/alerts\/rules'\)/)
    expect(src).toMatch(/const handleExportCsv = useCallback\(\(\) => \{\n    if \(unavailable\) return/)
    expect(src).toMatch(/onExport=\{unavailable \? undefined : handleExportCsv\}/)
    expect(src).toMatch(/exportDisabled=\{unavailable \|\| !filteredFindings\.length\}/)
    expect(src).toMatch(/onRefresh=\{fetchRules\}/)
    expect(src).not.toMatch(/setRules\(\[\]\)/)
  })
})
