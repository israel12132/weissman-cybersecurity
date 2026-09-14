import { describe, it, expect } from 'vitest'
import { readFileSync } from 'node:fs'
import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'

const src = readFileSync(
  join(dirname(fileURLToPath(import.meta.url)), 'VulnIntelDashboard.jsx'),
  'utf8',
)

describe('VulnIntelDashboard live-only truth', () => {
  it('does not paint severity KPI zeros when GET /api/findings fails', () => {
    expect(src).toMatch(/data-testid="vuln-intel-unavailable"/)
    expect(src).toMatch(/loading \|\| error \? '—'/)
    expect(src).toMatch(/!error && \(/)
  })

  it('does not paint leftover leftover-last-updated after a failed findings GET', () => {
    expect(src).toMatch(/lastUpdated=\{error \? null : lastUpdated\}/)
    expect(src).toMatch(/count=\{error \? null : filtered\.length\}/)
    expect(src).toMatch(/if \(error\) return/)
    expect(src).toMatch(/exportDisabled=\{\!\!error \|\| !filtered\.length\}/)
    expect(src).toMatch(/filtersExpanded && !error &&/)
  })

  it('mutes leftover leftover-truncation footer after a failed findings GET', () => {
    expect(src).toMatch(/\{!error && \(\n        <p className="text-\[10px\] font-mono text-\[var\(--text-disabled\)\] text-center">\n          \{t\('findings\.shown_of_total', \{ shown: filtered\.length, total \}\)/)
    expect(src).toMatch(/finding=\{error \? null : selected\}/)
    expect(src).toMatch(/setError\(e\.message \|\| 'Failed to load findings'\)/)
    expect(src).not.toMatch(/catch \(e\) \{\s*setFindings\(\[\]\)/)
    expect(src).not.toMatch(/catch \(e\) \{\s*setTotal\(null\)/)
  })

  it('mutes leftover leftover-GET Export CSV after a failed findings GET', () => {
    expect(src).toMatch(/apiFetch\(`\/api\/findings\?\$\{qs\}`/)
    expect(src).toMatch(/\{!error && \(\s*<Button variant="unstyled"\s*type="button"\s*onClick=\{exportCsv\}/)
    expect(src).toMatch(/if \(error\) return/)
    expect(src).toMatch(/vuln_intel\.export_csv/)
    expect(src).toMatch(/setError\(e\.message \|\| 'Failed to load findings'\)/)
  })
})
