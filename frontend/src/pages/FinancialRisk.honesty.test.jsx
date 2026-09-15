import { describe, it, expect } from 'vitest'
import { readFileSync } from 'node:fs'
import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'

const src = readFileSync(
  join(dirname(fileURLToPath(import.meta.url)), 'FinancialRisk.jsx'),
  'utf8',
)

describe('FinancialRisk live-only truth', () => {
  it('does not dump leftover leftover-contributors CSV after a failed FAIR GET', () => {
    expect(src).toMatch(/const handleExportCsv = useCallback\(\(\) => \{\n    if \(error\) return/)
    expect(src).toMatch(/exportDisabled=\{\!\!error \|\| !contributors\.length\}/)
    expect(src).toMatch(/\} catch \(e\) \{\n        setError/)
    expect(src).not.toMatch(/\} catch \(e\) \{\n        setSnapshot\(null\)/)
  })

  it('mutes leftover leftover-GET Export CSV after a failed FAIR GET', () => {
    expect(src).toMatch(/apiFetch\(`\/api\/financial-risk\/\$\{encodeURIComponent\(selectedClientId\)\}\$\{qs\}`\)/)
    expect(src).toMatch(/const handleExportCsv = useCallback\(\(\) => \{\n    if \(error\) return/)
    expect(src).toMatch(/onExport=\{error \? undefined : handleExportCsv\}/)
    expect(src).toMatch(/exportDisabled=\{\!\!error \|\| !contributors\.length\}/)
    expect(src).toMatch(/setError\(e\.message \|\| t\(`\$\{NS\}\.load_failed`\)\)/)
    expect(src).not.toMatch(/\} catch \(e\) \{\n        setSnapshot\(null\)/)
  })
})
