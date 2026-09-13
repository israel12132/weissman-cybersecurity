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
    expect(src).toMatch(/const exportCsv = useCallback\(\(\) => \{\n    if \(error\) return/)
    expect(src).toMatch(/const exportPdf = useCallback\(\(\) => \{\n    if \(error\) return/)
    expect(src).toMatch(/exportDisabled=\{\!\!error \|\| !filteredHosts\.length\}/)
    expect(src).toMatch(/disabled=\{\!\!error \|\| !filteredHosts\.length\}/)
    expect(src).toMatch(/\{data && !error && \(/)
    expect(src).not.toMatch(/setData\(null\)/)
  })
})
