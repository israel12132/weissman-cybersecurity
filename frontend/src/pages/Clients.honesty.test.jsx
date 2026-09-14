import { describe, it, expect } from 'vitest'
import { readFileSync } from 'node:fs'
import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'

const src = readFileSync(
  join(dirname(fileURLToPath(import.meta.url)), 'Clients.jsx'),
  'utf8',
)

describe('Clients live-only truth', () => {
  it('does not paint leftover leftover-last-updated after a failed clients GET', () => {
    expect(src).toMatch(/lastUpdated=\{error \? null : lastUpdated\}/)
    expect(src).toMatch(/count=\{error \? null : clients\.length\}/)
    expect(src).toMatch(/\) : !error && clients\.length > 0 \? \(/)
    expect(src).toMatch(/const handleExportCsv = useCallback\(\(\) => \{\n    if \(error\) return/)
    expect(src).toMatch(/exportDisabled=\{\!\!error \|\| !filteredFindings\.length\}/)
  })

  it('mutes leftover leftover-GET Export CSV after a failed clients GET', () => {
    expect(src).toMatch(/apiFetch\('\/api\/clients'\)/)
    expect(src).toMatch(/const handleExportCsv = useCallback\(\(\) => \{\n    if \(error\) return/)
    expect(src).toMatch(/onExport=\{error \? undefined : handleExportCsv\}/)
    expect(src).toMatch(/exportDisabled=\{\!\!error \|\| !filteredFindings\.length\}/)
    expect(src).toMatch(/onRefresh=\{loadClients\}/)
    expect(src).toMatch(/role="alert"/)
    expect(src).not.toMatch(/scan_failed[\s\S]{0,200}setError/)
    expect(src).not.toMatch(/delete_failed[\s\S]{0,200}setError/)
  })
})
