import { describe, it, expect } from 'vitest'
import { readFileSync } from 'node:fs'
import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'

const src = readFileSync(
  join(dirname(fileURLToPath(import.meta.url)), 'Billing.jsx'),
  'utf8',
)

describe('Billing live-only truth', () => {
  it('mutes leftover leftover-GET Export CSV after a failed usage GET', () => {
    expect(src).toMatch(/apiFetch\('\/api\/billing\/usage'\)/)
    expect(src).toMatch(/const handleExportCsv = useCallback\(\(\) => \{\n {4}if \(error\) return/)
    expect(src).toMatch(/onExport=\{error \? undefined : handleExportCsv\}/)
    expect(src).toMatch(/exportDisabled=\{!!error \|\| !filteredFindings\.length\}/)
    expect(src).toMatch(/setError\(err\.message \|\| t\('pages\.billing\.load_failed'\)\)/)
    expect(src).toMatch(/setCheckoutError/)
  })
})
