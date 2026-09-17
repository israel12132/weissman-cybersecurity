import { describe, it, expect } from 'vitest'
import { readFileSync } from 'node:fs'
import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'

const src = readFileSync(
  join(dirname(fileURLToPath(import.meta.url)), 'IncidentResponseCenter.jsx'),
  'utf8',
)

describe('IncidentResponseCenter live-only truth', () => {
  it('does not paint IR MetricCard zeros when GET /api/soc/incidents fails', () => {
    expect(src).toMatch(/data-testid="incident-response-unavailable"/)
    expect(src).toMatch(/unavailable_title/)
    expect(src).toMatch(/!Array\.isArray\(data\?\.incidents\)/)
    expect(src).toMatch(/error \? \(/)
  })

  it('does not paint leftover leftover-incident counts after a failed incidents GET', () => {
    expect(src).toMatch(/count: error \? '—' : incidents\.length/)
    expect(src).toMatch(/const handleExportCsv = useCallback\(\(\) => \{\n    if \(incidentsUnavailable\) return/)
    expect(src).toMatch(/exportDisabled=\{\!\!error \|\| !filteredFindings\.length\}/)
  })

  it('mutes leftover leftover-GET Export CSV after a failed incidents GET', () => {
    expect(src).toMatch(/apiFetch\('\/api\/soc\/incidents'\)/)
    expect(src).toMatch(/const handleExportCsv = useCallback\(\(\) => \{\n    if \(incidentsUnavailable\) return/)
    expect(src).toMatch(/onExport=\{incidentsUnavailable \? undefined : handleExportCsv\}/)
    expect(src).toMatch(/exportDisabled=\{\!\!error \|\| !filteredFindings\.length\}/)
    expect(src).toMatch(/setIncidentsUnavailable\(true\)/)
    expect(src).toMatch(/setError\(e\.message \?\? t\('pages\.incidentResponseCenter\.save_step_failed'\)\)/)
    expect(src).not.toMatch(/save_step_failed[\s\S]{0,120}setIncidentsUnavailable/)
    expect(src).not.toMatch(/setIncidents\(\[\]\)/)
  })
})
