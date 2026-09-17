import { describe, it, expect } from 'vitest'
import { readFileSync } from 'node:fs'
import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'

const src = readFileSync(
  join(dirname(fileURLToPath(import.meta.url)), 'BaselineAndDrift.jsx'),
  'utf8',
)

describe('BaselineAndDrift live-only truth', () => {
  it('does not paint leftover leftover-anomalies after a failed baseline GET', () => {
    expect(src).toMatch(/data-testid="baseline-unavailable"/)
    expect(src).toMatch(/anomalies_heading', \{ count: error \? '—' : filteredAnomalies\.length \}/)
    expect(src).toMatch(/error \? s : `\$\{s\} \(\$\{severityCounts\[s\] \|\| 0\}\)`/)
    expect(src).toMatch(/const handleExportCsv = useCallback\(\(\) => \{\n {4}if \(error\) return/)
    expect(src).toMatch(/exportDisabled=\{!!error \|\| !filteredFindings\.length\}/)
  })

  it('mutes leftover leftover-GET Export CSV after a failed baseline GET', () => {
    expect(src).toMatch(/api\.get\(`\/api\/baseline\/anomalies\?range=\$\{timeRange\}&limit=200`\)/)
    expect(src).toMatch(/const handleExportCsv = useCallback\(\(\) => \{\n {4}if \(error\) return/)
    expect(src).toMatch(/onExport=\{error \? undefined : handleExportCsv\}/)
    expect(src).toMatch(/exportDisabled=\{!!error \|\| !filteredFindings\.length\}/)
    expect(src).toMatch(/onRefresh=\{fetchData\}/)
    expect(src).not.toMatch(/Failed to fetch baseline data:[\s\S]{0,80}setAnomalies\(\[\]\)/)
    expect(src).not.toMatch(/Failed to fetch baseline data:[\s\S]{0,80}setDriftData\(\[\]\)/)
    expect(src).not.toMatch(/Failed to fetch baseline data:[\s\S]{0,80}setBaseline\(/)
  })
})
