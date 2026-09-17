import { describe, it, expect } from 'vitest'
import { readFileSync } from 'node:fs'
import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'

const src = readFileSync(
  join(dirname(fileURLToPath(import.meta.url)), 'SsoDashboard.jsx'),
  'utf8',
)

describe('SsoDashboard live-only truth', () => {
  it('does not paint no-IdPs when the directory store is down', () => {
    expect(src).toMatch(/setIdpsUnavailable\(true\)/)
    expect(src).toMatch(/data-testid="sso-idps-unavailable"/)
    expect(src).toMatch(/!idpsUnavailable && idps\.length === 0/)
  })

  it('does not paint leftover leftover-IdP counts after a failed IdP GET', () => {
    expect(src).toMatch(/idps\.length > 0 && !idpsUnavailable &&/)
    expect(src).toMatch(/!loading && !idpsUnavailable && idps\.length > 0 && \(/)
    expect(src).toMatch(/!idpsUnavailable && visibleIdps\.map/)
    expect(src).toMatch(/const handleExportCsv = useCallback\(\(\) => \{\n {4}if \(idpsUnavailable\) return/)
    expect(src).toMatch(/exportDisabled=\{idpsUnavailable \|\| !filteredFindings\.length\}/)
  })

  it('mutes leftover leftover-GET Export CSV after a failed IdP GET', () => {
    expect(src).toMatch(/api\.get\('\/api\/sso\/idps'\)/)
    expect(src).toMatch(/const handleExportCsv = useCallback\(\(\) => \{\n {4}if \(idpsUnavailable\) return/)
    expect(src).toMatch(/onExport=\{idpsUnavailable \? undefined : handleExportCsv\}/)
    expect(src).toMatch(/exportDisabled=\{idpsUnavailable \|\| !filteredFindings\.length\}/)
    expect(src).toMatch(/onRefresh=\{fetchIdps\}/)
    expect(src).toMatch(/showToast\(t\('pages\.ssoDashboard\.save_failed', \{ message: e\.message \}\), false\)/)
    expect(src).not.toMatch(/save_failed[\s\S]{0,80}setIdpsUnavailable/)
    expect(src).not.toMatch(/setIdpsUnavailable\(true\)\n {6}showToast[\s\S]{0,80}setIdps\(/)
  })
})
