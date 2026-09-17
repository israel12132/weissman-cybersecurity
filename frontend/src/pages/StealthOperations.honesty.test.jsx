import { describe, it, expect } from 'vitest'
import { readFileSync } from 'node:fs'
import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'

const src = readFileSync(
  join(dirname(fileURLToPath(import.meta.url)), 'StealthOperations.jsx'),
  'utf8',
)

describe('StealthOperations live-only truth', () => {
  it('does not paint leftover leftover-stealth KPIs after a failed status GET', () => {
    expect(src).toMatch(/const exportCsv = useCallback\(\(\) => \{\n {4}if \(error\) return/)
    expect(src).toMatch(/const exportPdf = useCallback\(\(\) => \{\n {4}if \(error\) return/)
    expect(src).toMatch(/exportDisabled=\{!!error \|\| !filteredHosts\.length\}/)
    expect(src).toMatch(/disabled=\{!!error \|\| !filteredHosts\.length\}/)
    expect(src).toMatch(/\{data && !error && \(/)
    expect(src).not.toMatch(/setData\(null\)/)
  })

  it('mutes leftover leftover-GET Export CSV and PDF after a failed status GET', () => {
    expect(src).toMatch(/apiFetch\('\/api\/stealth\/status'\)/)
    expect(src).toMatch(/onExport=\{error \? undefined : exportCsv\}/)
    expect(src).toMatch(/\{!error && \(\s*<Button\s*variant="unstyled"\s*type="button"\s*onClick=\{exportPdf\}/)
    expect(src).toMatch(/setError\(\(err && err\.message\) \|\| 'request failed'\)/)
    expect(src).toMatch(/setSaveMsg\(\{ ok: false, text: \(err && err\.message\) \|\| 'save failed' \}\)/)
    expect(src).not.toMatch(/setData\(null\)/)
  })
})
