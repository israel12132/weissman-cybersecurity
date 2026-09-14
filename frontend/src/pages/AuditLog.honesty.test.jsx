import { describe, it, expect } from 'vitest'
import { readFileSync } from 'node:fs'
import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'

const src = readFileSync(
  join(dirname(fileURLToPath(import.meta.url)), 'AuditLog.jsx'),
  'utf8',
)

describe('AuditLog live-only truth', () => {
  it('does not paint audit KPI zeros when GET /api/audit-logs fails', () => {
    expect(src).toMatch(/data-testid="audit-log-unavailable"/)
    expect(src).toMatch(/unavailable_title/)
    expect(src).toMatch(/loading \|\| error \? '—'/)
  })

  it('does not paint leftover leftover-audit rows after a failed audit-logs GET', () => {
    expect(src).toMatch(/data=\{error \? \[\] : filteredEntries\}/)
    expect(src).toMatch(/shown: error \? '—' : filteredEntries\.length/)
    expect(src).toMatch(/const handleExportCsv = useCallback\(\(\) => \{\n    if \(error\) return/)
    expect(src).toMatch(/exportDisabled=\{\!\!error \|\| filteredEntries\.length === 0\}/)
    expect(src).toMatch(/!error && total > 0 && \(/)
    expect(src).not.toMatch(/setEntries\(\[\]\)/)
  })

  it('mutes leftover leftover-GET Export Full JSON after a failed audit-logs GET', () => {
    expect(src).toMatch(/apiFetch\(`\/api\/audit-logs\?\$\{qs\.toString\(\)\}`/)
    expect(src).toMatch(/const exportFull = useCallback\(async \(\) => \{\n    if \(error\) return/)
    expect(src).toMatch(/\{!error && \(\s*<Button variant="unstyled"\s*type="button"\s*onClick=\{exportFull\}/)
    expect(src).toMatch(/audit\.export_full/)
    expect(src).toMatch(/setError\(e\.message \|\| t\('audit\.load_error'\)\)/)
  })

  it('mutes leftover leftover-GET Export CSV after a failed audit-logs GET', () => {
    expect(src).toMatch(/apiFetch\(`\/api\/audit-logs\?\$\{qs\.toString\(\)\}`/)
    expect(src).toMatch(/const handleExportCsv = useCallback\(\(\) => \{\n    if \(error\) return/)
    expect(src).toMatch(/onExport=\{error \? undefined : handleExportCsv\}/)
    expect(src).toMatch(/exportDisabled=\{\!\!error \|\| filteredEntries\.length === 0\}/)
    expect(src).toMatch(/setError\(e\.message \|\| t\('audit\.load_error'\)\)/)
    expect(src).not.toMatch(/setEntries\(\[\]\)/)
  })
})
