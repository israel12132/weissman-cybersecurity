import { describe, it, expect } from 'vitest'
import { readFileSync } from 'node:fs'
import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'

const src = readFileSync(
  join(dirname(fileURLToPath(import.meta.url)), 'SocialEngineering.jsx'),
  'utf8',
)

describe('SocialEngineering live-only truth', () => {
  it('does not paint zero campaigns when assessments or clients are unconfirmed', () => {
    expect(src).toMatch(/data-testid="social-engineering-unavailable"/)
    expect(src).toMatch(/data-testid="social-engineering-clients-unavailable"/)
    expect(src).toMatch(/unavailable_title/)
    expect(src).toMatch(/loading \|\| error \? '—'/)
    expect(src).toMatch(/!error && \(/)
    expect(src).toMatch(/!Array\.isArray\(data\.campaigns\)/)
    expect(src).toMatch(/Array\.isArray\(data\?\.clients\)/)
    expect(src).not.toMatch(/\.catch\(\(\) => \{\}\)/)
  })

  it('does not dump leftover leftover-campaigns CSV after a failed assessments GET', () => {
    expect(src).toMatch(/const handleExportCsv = useCallback\(\(\) => \{\n    if \(campaignsUnavailable\) return/)
    expect(src).toMatch(/exportDisabled=\{\!\!error \|\| !filteredFindings\.length\}/)
  })

  it('mutes leftover leftover-GET Export CSV after a failed assessments GET', () => {
    expect(src).toMatch(/apiFetch\('\/api\/soc\/social-engineering'\)/)
    expect(src).toMatch(/const handleExportCsv = useCallback\(\(\) => \{\n    if \(campaignsUnavailable\) return/)
    expect(src).toMatch(/onExport=\{campaignsUnavailable \? undefined : handleExportCsv\}/)
    expect(src).toMatch(/exportDisabled=\{\!\!error \|\| !filteredFindings\.length\}/)
    expect(src).toMatch(/setCampaignsUnavailable\(true\)/)
    expect(src).toMatch(/setError\(e\?\.message \|\| t\('pages\.socialEngineering\.scan_failed'\)\)/)
    expect(src).not.toMatch(/scan_failed[\s\S]{0,120}setCampaignsUnavailable/)
    expect(src).not.toMatch(/setCampaigns\(\[\]\)/)
  })
})
