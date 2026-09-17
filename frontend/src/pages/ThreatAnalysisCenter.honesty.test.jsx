import { describe, it, expect } from 'vitest'
import { readFileSync } from 'node:fs'
import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'

const src = readFileSync(
  join(dirname(fileURLToPath(import.meta.url)), 'ThreatAnalysisCenter.jsx'),
  'utf8',
)

describe('ThreatAnalysisCenter live-only truth', () => {
  it('mutes leftover leftover-GET Export CSV after a failed threat-analysis GET', () => {
    expect(src).toMatch(/api\.get\(`\/api\/threat-analysis\/\$\{cid\}`\)/)
    expect(src).toMatch(/const handleExportCsv = useCallback\(\(\) => \{\n    if \(error\) return/)
    expect(src).toMatch(/onExport=\{error \? undefined : handleExportCsv\}/)
    expect(src).toMatch(/exportDisabled=\{\!\!error \|\| !filteredFindings\.length\}/)
    expect(src).toMatch(/setError\(e\?\.message \|\| 'Failed to load threat analysis'\)/)
    expect(src).toMatch(/setReport\(null\)/)
    expect(src).toMatch(/setPersistedNote\(e\?\.message \|\| 'Persist failed/)
  })
})
