import { describe, it, expect } from 'vitest'
import { readFileSync } from 'node:fs'
import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'

const src = readFileSync(
  join(dirname(fileURLToPath(import.meta.url)), 'SBOMBrowser.jsx'),
  'utf8',
)

describe('SBOMBrowser live-only truth', () => {
  it('does not paint a clean SBOM when components fetch fails', () => {
    expect(src).toMatch(/data-testid="sbom-browser-unavailable"/)
    expect(src).toMatch(/unavailable_title/)
    expect(src).toMatch(/showUnavailable/)
    expect(src).toMatch(/!error && components\.length === 0/)
  })

  it('does not dump leftover leftover-SBOM CSV after a failed components GET', () => {
    expect(src).toMatch(/const handleExportCsv = useCallback\(\(\) => \{\n {4}if \(error\) return/)
    expect(src).toMatch(/exportDisabled=\{!!error \|\| !filteredFindings\.length\}/)
  })

  it('mutes leftover leftover-GET Export CSV after a failed components GET', () => {
    expect(src).toMatch(/api\.get\(withClientId\('\/api\/sbom\/components', cid\)\)/)
    expect(src).toMatch(/const handleExportCsv = useCallback\(\(\) => \{\n {4}if \(error\) return/)
    expect(src).toMatch(/onExport=\{error \? undefined : handleExportCsv\}/)
    expect(src).toMatch(/exportDisabled=\{!!error \|\| !filteredFindings\.length\}/)
    expect(src).toMatch(/onRefresh=\{\(\) => fetchSBOM\(clientId\)\}/)
    expect(src).toMatch(/setError\(t\('pages\.sbomBrowser\.export_failed'\)\)/)
    expect(src).not.toMatch(/export_failed[\s\S]{0,80}setComponents/)
  })
})
