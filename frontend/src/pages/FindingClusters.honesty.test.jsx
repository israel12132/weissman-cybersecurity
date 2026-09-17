import { describe, it, expect } from 'vitest'
import { readFileSync } from 'node:fs'
import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'

const src = readFileSync(
  join(dirname(fileURLToPath(import.meta.url)), 'FindingClusters.jsx'),
  'utf8',
)

describe('FindingClusters live-only truth', () => {
  it('does not dump leftover leftover-clusters CSV after a failed clusters GET', () => {
    expect(src).toMatch(/const handleExportCsv = useCallback\(\(\) => \{\n {4}if \(error\) return/)
    expect(src).toMatch(/exportDisabled=\{!!error \|\| !filtered\.length\}/)
    expect(src).not.toMatch(/setRows\(\[\]\)/)
  })

  it('mutes leftover leftover-GET Export CSV after a failed clusters GET', () => {
    expect(src).toMatch(/apiFetch\('\/api\/findings\/clusters\?limit=1000'\)/)
    expect(src).toMatch(/onExport=\{error \? undefined : handleExportCsv\}/)
    expect(src).toMatch(/onRefresh=\{load\}/)
    expect(src).toMatch(/data-testid="finding-clusters-unavailable"/)
    expect(src).not.toMatch(/setRows\(\[\]\)/)
  })
})
