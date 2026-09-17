import { describe, it, expect } from 'vitest'
import { readFileSync } from 'node:fs'
import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'

const src = readFileSync(
  join(dirname(fileURLToPath(import.meta.url)), 'FindingSuppressions.jsx'),
  'utf8',
)

describe('FindingSuppressions live-only truth', () => {
  it('does not dump leftover leftover-suppressions CSV after a failed suppressions GET', () => {
    expect(src).toMatch(/const handleExportCsv = useCallback\(\(\) => \{\n {4}if \(error\) return/)
    expect(src).toMatch(/exportDisabled=\{!!error \|\| !filtered\.length\}/)
    expect(src).not.toMatch(/setRows\(\[\]\)/)
  })

  it('mutes leftover leftover-GET Export CSV after a failed suppressions GET', () => {
    expect(src).toMatch(/apiFetch\('\/api\/intel\/suppressions'\)/)
    expect(src).toMatch(/onExport=\{error \? undefined : handleExportCsv\}/)
    expect(src).toMatch(/onRefresh=\{load\}/)
    expect(src).toMatch(/data-testid="finding-suppressions-unavailable"/)
    expect(src).toMatch(/method: 'DELETE'/)
    expect(src).toMatch(/toast\.error\(e\.message \|\| t\(`\$\{NS\}\.delete_failed`\)\)/)
    expect(src).not.toMatch(/delete_failed[\s\S]{0,80}setError/)
    expect(src).not.toMatch(/setRows\(\[\]\)/)
  })
})
