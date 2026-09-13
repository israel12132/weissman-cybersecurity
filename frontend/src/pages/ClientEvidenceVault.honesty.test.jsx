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
    expect(src).toMatch(/const handleExportCsv = useCallback\(\(\) => \{\n    if \(error\) return/)
    expect(src).toMatch(/exportDisabled=\{\!\!error \|\| !filteredFindings\.length\}/)
  })

  it('mutes leftover client name in the title after a failed client GET', () => {
    expect(src).toMatch(/title=\{!error && client\?\.name\n        \? t\('pages\.clientEvidenceVault\.title_with_client', \{ name: client\.name \}\)\n        : t\('pages\.clientEvidenceVault\.title'\)\}/)
    expect(src).toMatch(/setError\(e\?\.message \|\| t\('pages\.clientEvidenceVault\.network_error'\)\)/)
    expect(src).toMatch(/if \(clientR\.error\) \{\n        setError\(t\('pages\.clientEvidenceVault\.load_client_failed', \{ status: clientR\.error\.status \}\)\)\n        setLoading\(false\)\n        return/)
    expect(src).not.toMatch(/catch \(e\) \{\s*setClient\(null\)/)
  })
})
