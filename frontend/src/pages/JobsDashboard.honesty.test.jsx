import { describe, it, expect } from 'vitest'
import { readFileSync } from 'node:fs'
import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'

const src = readFileSync(
  join(dirname(fileURLToPath(import.meta.url)), 'JobsDashboard.jsx'),
  'utf8',
)

describe('JobsDashboard live-only truth', () => {
  it('does not paint status KPI zeros when GET /api/jobs is unconfirmed', () => {
    expect(src).toMatch(/data-testid="jobs-dashboard-unavailable"/)
    expect(src).toMatch(/unavailable_title/)
    expect(src).toMatch(/error && !hasLoadedRef\.current/)
    expect(src).toMatch(/data\.ok === false \|\| data\.unavailable === true/)
  })

  it('mutes leftover leftover-GET Export CSV after a failed jobs GET', () => {
    expect(src).toMatch(/apiFetch\(`\/api\/jobs\?\$\{qs\.toString\(\)\}`\)/)
    expect(src).toMatch(/const handleExportCsv = useCallback\(\(\) => \{\n {4}if \(error\) return/)
    expect(src).toMatch(/onExport=\{error \? undefined : handleExportCsv\}/)
    expect(src).toMatch(/exportDisabled=\{!filteredFindings\.length\}/)
    expect(src).toMatch(/error && !hasLoadedRef\.current/)
    expect(src).not.toMatch(/if \(hasLoadedRef\.current\) return/)
    expect(src).not.toMatch(/setJobs\(\[\]\)/)
  })

  it('mutes leftover leftover-GET status KPI tiles after a failed jobs GET', () => {
    expect(src).toMatch(/\{error \? '—' : statusCounts\[status\]\}/)
    expect(src).toMatch(/jobs_tracked', \{ count: error \? '—' : total \}/)
    expect(src).toMatch(/jobs_tracked_plural', \{ count: error \? '—' : total \}/)
    expect(src).toMatch(/onExport=\{error \? undefined : handleExportCsv\}/)
    expect(src).not.toMatch(/setJobs\(\[\]\)/)
    expect(src).not.toMatch(/method:\s*'POST'/)
  })
})
