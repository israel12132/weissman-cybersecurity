import { describe, it, expect } from 'vitest'
import { readFileSync } from 'node:fs'
import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'

const src = readFileSync(
  join(dirname(fileURLToPath(import.meta.url)), 'FixFirstProgram.jsx'),
  'utf8',
)

describe('FixFirstProgram live-only truth', () => {
  it('mutes leftover leftover-GET Export CSV and PDF after a failed priority GET', () => {
    expect(src).toMatch(/apiFetch\(`\/api\/remediation\/priority\/\$\{encodeURIComponent\(id\)\}\?limit=200`\)/)
    expect(src).toMatch(/const exportCsv = useCallback\(\(\) => \{\n {4}if \(error\) return/)
    expect(src).toMatch(/const exportPdf = useCallback\(\(\) => \{\n {4}if \(error\) return/)
    expect(src).toMatch(/onExport=\{error \? undefined : exportCsv\}/)
    expect(src).toMatch(/exportDisabled=\{!!error \|\| !filteredProgram\.length\}/)
    expect(src).toMatch(/\{!error && \(\s*<Button\s*variant="unstyled"\s*type="button"\s*onClick=\{exportPdf\}/)
    expect(src).toMatch(/setError\(e\?\.message \|\| 'load failed'\)/)
  })
})
