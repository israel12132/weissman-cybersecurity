import { describe, it, expect } from 'vitest'
import { readFileSync } from 'node:fs'
import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'

const src = readFileSync(
  join(dirname(fileURLToPath(import.meta.url)), 'ClientEngagements.jsx'),
  'utf8',
)

describe('ClientEngagements live-only truth', () => {
  it('does not dump leftover leftover-engagements CSV after a failed engagements GET', () => {
    expect(src).toMatch(/data-testid="engagements-empty-suppressed"/)
    expect(src).toMatch(/const handleExportCsv = useCallback\(\(\) => \{\n    if \(error\) return/)
    expect(src).toMatch(/exportDisabled=\{\!\!error \|\| !filteredFindings\.length\}/)
  })

  it('mutes leftover client name in the title after a failed client GET', () => {
    expect(src).toMatch(/title=\{!error && client\?\.name\n        \? t\('pages\.clientEngagements\.title_with_client', \{ name: client\.name \}\)\n        : t\('pages\.clientEngagements\.title'\)\}/)
    expect(src).toMatch(/setError\(e\?\.message \|\| t\('pages\.clientEngagements\.network_error'\)\)/)
    expect(src).toMatch(/if \(clientR\.error\) \{\n        setError\(t\('pages\.clientEngagements\.load_client_failed', \{ status: clientR\.error\.status \}\)\)\n        setLoading\(false\)\n        return/)
    expect(src).not.toMatch(/catch \(e\) \{\s*setClient\(null\)/)
  })
})
