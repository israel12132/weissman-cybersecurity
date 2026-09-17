import { describe, it, expect } from 'vitest'
import { readFileSync } from 'node:fs'
import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'

const src = readFileSync(
  join(dirname(fileURLToPath(import.meta.url)), 'ThreatHuntingWorkbench.jsx'),
  'utf8',
)

describe('ThreatHuntingWorkbench live-only truth', () => {
  it('does not paint active-hunt zeros when GET /api/soc/hunts fails', () => {
    expect(src).toMatch(/data-testid="threat-hunting-unavailable"/)
    expect(src).toMatch(/unavailable_title/)
    expect(src).toMatch(/campaignsError \? \(\s*<div data-testid="threat-hunting-unavailable"/)
  })

  it('mutes leftover leftover-GET Export CSV after a failed hunts GET', () => {
    expect(src).toMatch(/apiFetch\('\/api\/soc\/hunts'\)/)
    expect(src).toMatch(/const handleExportCsv = useCallback\(\(\) => \{\n {4}if \(campaignsError\) return/)
    expect(src).toMatch(/onExport=\{campaignsError \? undefined : handleExportCsv\}/)
    expect(src).toMatch(/exportDisabled=\{!filteredFindings\.length\}/)
    expect(src).toMatch(/setCampaignsError\(e\?\.status \? t\(`\$\{NS\}\.load_error`, \{ status: e\.status \}\) : \(e\.message \|\| String\(e\)\)\)/)
    expect(src).toMatch(/setCampaigns\(\[\]\)/)
    expect(src).toMatch(/setIocs\(\[\]\)/)
    expect(src).toMatch(/setQueries\(\[\]\)/)
  })
})
