import { describe, it, expect } from 'vitest'
import { readFileSync } from 'node:fs'
import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'

const src = readFileSync(
  join(dirname(fileURLToPath(import.meta.url)), 'ComplianceFrameworks.jsx'),
  'utf8',
)

describe('ComplianceFrameworks live-only truth', () => {
  it('does not paint an unmapped tenant when GET /api/compliance/frameworks fails', () => {
    expect(src).toMatch(/data-testid="compliance-frameworks-unavailable"/)
    expect(src).toMatch(/unavailable_title/)
    expect(src).not.toMatch(/setFrameworks\(\[\]\)/)
    expect(src).toMatch(/data-testid="compliance-controls-unavailable"/)
    expect(src).toMatch(/controls_unavailable_title/)
    expect(src).toMatch(/setControlsUnavailable\(true\)/)
    expect(src).not.toMatch(/setControls\(\[\]\)/)
  })

  it('does not dump leftover leftover-controls after a failed frameworks GET', () => {
    expect(src).toMatch(/selectedFramework && !error && \(/)
    expect(src).toMatch(/controlsUnavailable \? '—' : filteredControls\.length/)
    expect(src).toMatch(/const handleExportCsv = useCallback\(\(\) => \{\n    if \(error \|\| controlsUnavailable\) return/)
    expect(src).toMatch(/exportDisabled=\{\!\!error \|\| controlsUnavailable \|\| !filteredFindings\.length\}/)
    expect(src).toMatch(/disabled=\{exporting \|\| controlsUnavailable \|\| !!error \|\| controls\.length === 0\}/)
    expect(src).toMatch(/const generateReport = async \(frameworkId\) => \{\n    if \(error \|\| controlsUnavailable\) return/)
    expect(src).toMatch(/selectedFramework && !error && !controlsUnavailable && stats\.nonCompliant > 0 && \(/)
  })
})
