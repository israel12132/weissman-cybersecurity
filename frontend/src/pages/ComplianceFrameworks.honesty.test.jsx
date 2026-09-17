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
    expect(src).toMatch(/const handleExportCsv = useCallback\(\(\) => \{\n {4}if \(error \|\| controlsUnavailable\) return/)
    expect(src).toMatch(/exportDisabled=\{!!error \|\| controlsUnavailable \|\| !filteredFindings\.length\}/)
    expect(src).toMatch(/disabled=\{exporting \|\| controlsUnavailable \|\| !!error \|\| controls\.length === 0\}/)
    expect(src).toMatch(/const generateReport = async \(frameworkId\) => \{\n {4}if \(error \|\| controlsUnavailable\) return/)
    expect(src).toMatch(/selectedFramework && !error && !controlsUnavailable && stats\.nonCompliant > 0 && \(/)
    expect(src).toMatch(/isSelected && !controlsUnavailable && controls\.length > 0/)
  })

  it('mutes leftover leftover-GET Export CSV after a failed frameworks GET', () => {
    expect(src).toMatch(/api\.get\('\/api\/compliance\/frameworks'\)/)
    expect(src).toMatch(/onExport=\{error \? undefined : handleExportCsv\}/)
    expect(src).toMatch(/setError\(err\?\.message \|\| t\('pages\.complianceFrameworks\.load_failed'\)\)/)
    expect(src).not.toMatch(/catch \(err\) \{\s*console\.error\('Failed to fetch frameworks:', err\);\s*setFrameworks\(\[\]\)/)
  })

  it('mutes leftover framework name in pack-scope after a failed frameworks GET', () => {
    expect(src).toMatch(/framework: !error && selectedFramework\?\.name \? selectedFramework\.name : t\('pages\.complianceFrameworks\.pack_all_frameworks'\)/)
    expect(src).toMatch(/setError\(err\?\.message \|\| t\('pages\.complianceFrameworks\.load_failed'\)\)/)
    expect(src).not.toMatch(/catch \(err\) \{\s*console\.error\('Failed to fetch frameworks:', err\);\s*setSelectedFramework\(null\)/)
    expect(src).not.toMatch(/catch \(err\) \{\s*console\.error\('Failed to fetch frameworks:', err\);\s*setFrameworks\(\[\]\)/)
  })

  it('does not paint idle empty mappings after leftover leftover-GET control-mappings fails', () => {
    expect(src).toMatch(/apiFetch\(`\/api\/compliance\/control-mappings\$\{fw\}`\)/)
    expect(src).toMatch(/setMappings\(\[\]\)/)
    expect(src).toMatch(/setMappingsUnavailable\(true\)/)
    expect(src).toMatch(/if \(mappings != null && !mappingsUnavailable\) return/)
    expect(src).toMatch(/data-testid="compliance-mappings-unavailable"/)
    expect(src).toMatch(/mappings_unavailable_title/)
    expect(src).toMatch(/Array\.isArray\(mappings\) && !mappingsUnavailable/)
    expect(src).not.toMatch(/export_failed[\s\S]{0,200}setMappingsUnavailable/)
    expect(src).not.toMatch(/pack_failed[\s\S]{0,200}setMappingsUnavailable/)
    expect(src).not.toMatch(/export_failed[\s\S]{0,200}setMappings\(\[\]\)/)
    expect(src).not.toMatch(/pack_failed[\s\S]{0,200}setMappings\(\[\]\)/)
  })
})
