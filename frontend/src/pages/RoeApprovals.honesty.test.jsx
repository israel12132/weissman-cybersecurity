import { describe, it, expect } from 'vitest'
import { readFileSync } from 'node:fs'
import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'

const src = readFileSync(
  join(dirname(fileURLToPath(import.meta.url)), 'RoeApprovals.jsx'),
  'utf8',
)

describe('RoeApprovals live-only truth', () => {
  it('does not paint a clear dual-control queue when GET /api/roe/override-requests fails', () => {
    expect(src).toMatch(/data-testid="roe-approvals-unavailable"/)
    expect(src).toMatch(/unavailable_title/)
    expect(src).toMatch(/error \? t\('pages\.roeApprovals\.pending', \{ count: '—' \}\)/)
    expect(src).toMatch(/error \? null : \(/)
    expect(src).not.toMatch(/setRequests\(\[\]\)/)
  })

  it('does not dump leftover leftover-approvals CSV after a failed queue GET', () => {
    expect(src).toMatch(/const handleExportCsv = useCallback\(\(\) => \{\n {4}if \(error\) return/)
    expect(src).toMatch(/exportDisabled=\{!!error \|\| !filteredFindings\.length\}/)
  })

  it('mutes leftover leftover-GET Export CSV after a failed queue GET', () => {
    expect(src).toMatch(/apiFetch\('\/api\/roe\/override-requests\?status=pending'\)/)
    expect(src).toMatch(/const handleExportCsv = useCallback\(\(\) => \{\n {4}if \(error\) return/)
    expect(src).toMatch(/onExport=\{error \? undefined : handleExportCsv\}/)
    expect(src).toMatch(/exportDisabled=\{!!error \|\| !filteredFindings\.length\}/)
    expect(src).toMatch(/onRefresh=\{load\}/)
    expect(src).toMatch(/toast\.error\(b\?\.detail \|\| t\('pages\.roeApprovals\.approve_failed'/)
    expect(src).not.toMatch(/approve_failed[\s\S]{0,80}setError/)
    expect(src).not.toMatch(/setRequests\(\[\]\)/)
  })
})
