import { describe, it, expect } from 'vitest'
import { readFileSync } from 'node:fs'
import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'

const src = readFileSync(
  join(dirname(fileURLToPath(import.meta.url)), 'UebaAnomalies.jsx'),
  'utf8',
)

describe('UebaAnomalies live-only truth', () => {
  it('does not dump leftover leftover-anomalies CSV after a failed UEBA GET', () => {
    expect(src).toMatch(/const handleExportCsv = useCallback\(\(\) => \{\n    if \(error\) return/)
    expect(src).toMatch(/exportDisabled=\{\!\!error \|\| !filtered\.length\}/)
    expect(src).not.toMatch(/setAnomalies\(\[\]\)/)
  })

  it('mutes leftover leftover-GET Export CSV after a failed UEBA anomalies GET', () => {
    expect(src).toMatch(/apiFetch\('\/api\/ueba\/anomalies\?limit=500'\)/)
    expect(src).toMatch(/onExport=\{error \? undefined : handleExportCsv\}/)
    expect(src).toMatch(/onRefresh=\{load\}/)
    expect(src).toMatch(/data-testid="ueba-anomalies-unavailable"/)
    expect(src).not.toMatch(/setAnomalies\(\[\]\)/)
  })
})
