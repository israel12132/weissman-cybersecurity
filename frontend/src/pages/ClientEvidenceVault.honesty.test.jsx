import { describe, it, expect } from 'vitest'
import { readFileSync } from 'node:fs'
import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'

const src = readFileSync(
  join(dirname(fileURLToPath(import.meta.url)), 'ClientEvidenceVault.jsx'),
  'utf8',
)

describe('ClientEvidenceVault live-only truth', () => {
  it('does not window.open a download that cannot surface 503', () => {
    expect(src).not.toMatch(/window\.open/)
    expect(src).toMatch(/raw:\s*true/)
    expect(src).toMatch(/\/api\/evidence\/\$\{item\.id\}\/download/)
    expect(src).toMatch(/download_failed/)
  })

  it('does not dump leftover leftover-evidence CSV after a failed evidence GET', () => {
    expect(src).toMatch(/const handleExportCsv = useCallback\(\(\) => \{\n {4}if \(error\) return/)
    expect(src).toMatch(/exportDisabled=\{!!error \|\| !filteredFindings\.length\}/)
  })

  it('mutes leftover client name in the title after a failed client GET', () => {
    expect(src).toMatch(/title=\{!error && client\?\.name\n {8}\? t\('pages\.clientEvidenceVault\.title_with_client', \{ name: client\.name \}\)\n {8}: t\('pages\.clientEvidenceVault\.title'\)\}/)
    expect(src).toMatch(/setError\(e\?\.message \|\| t\('pages\.clientEvidenceVault\.network_error'\)\)/)
    expect(src).toMatch(/if \(clientR\.error\) \{\n {8}setError\(t\('pages\.clientEvidenceVault\.load_client_failed', \{ status: clientR\.error\.status \}\)\)\n {8}setEvidenceUnavailable\(true\)\n {8}setLoading\(false\)\n {8}return/)
    expect(src).not.toMatch(/catch \(e\) \{\s*setClient\(null\)/)
  })

  it('mutes leftover leftover-GET Export CSV after a failed evidence GET', () => {
    expect(src).toMatch(/apiFetch\(`\/api\/clients\/\$\{clientId\}\/evidence`\)/)
    expect(src).toMatch(/onExport=\{evidenceUnavailable \? undefined : handleExportCsv\}/)
    expect(src).toMatch(/onRefresh=\{loadAll\}/)
    expect(src).toMatch(/data-testid="evidence-unavailable"/)
    expect(src).toMatch(/setError\(e\?\.message \|\| t\('pages\.clientEvidenceVault\.upload_failed'\)\)/)
    expect(src).toMatch(/setEvidenceUnavailable\(true\)/)
    expect(src).not.toMatch(/onExport=\{handleExportCsv\}/)
    expect(src).not.toMatch(/uploadEvidence[\s\S]{0,800}setEvidenceUnavailable/)
  })
})
