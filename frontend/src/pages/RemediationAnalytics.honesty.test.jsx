import { describe, it, expect } from 'vitest'
import { readFileSync } from 'node:fs'
import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'

const src = readFileSync(
  join(dirname(fileURLToPath(import.meta.url)), 'RemediationAnalytics.jsx'),
  'utf8',
)

describe('RemediationAnalytics live-only truth', () => {
  it('does not paint quiet heal totals when findings or heal-stats are unconfirmed', () => {
    expect(src).toMatch(/data-testid="remediation-analytics-unavailable"/)
    expect(src).toMatch(/unavailable_title/)
    expect(src).toMatch(/results\.some\(\(x\) => x\.status === 'rejected'\)/)
    expect(src).toMatch(/setHealStats\(null\)/)
    expect(src).toMatch(/heals == null/)
    expect(src).toMatch(/error \|\| partial/)
    expect(src).toMatch(/Array\.isArray\(d\?\.findings\) \? d\.findings : null/)
    expect(src).not.toMatch(/\.catch\(\(\) => null\)/)
  })

  it('does not paint leftover leftover-heals after a failed findings GET', () => {
    expect(src).toMatch(/const exportCsv = useCallback\(\(\) => \{\n {4}if \(error\) return/)
    expect(src).toMatch(/const exportPdf = useCallback\(\(\) => \{\n {4}if \(error\) return/)
    expect(src).toMatch(/exportDisabled=\{!!error \|\| !filteredHeals\.length\}/)
    expect(src).toMatch(/disabled=\{!!error \|\| !filteredHeals\.length\}/)
    expect(src).toMatch(/<div hidden=\{!!error\}>\n {10}<HealTrendSparkline/)
    expect(src).toMatch(/bounded && !error && !loading && !statsLoading && healStats/)
    expect(src).toMatch(/\{\/\* Recent heals feed — leftover rows stay in React state; mute paint on failed findings GET \*\/\}\n {8}\{!error && \(/)
    expect(src).not.toMatch(/setFindings\(\[\]\)/)
  })

  it('mutes leftover leftover-GET Export CSV and PDF after a failed findings GET', () => {
    expect(src).toMatch(/apiFetch\('\/api\/findings\?limit=2000'\)/)
    expect(src).toMatch(/onExport=\{error \? undefined : exportCsv\}/)
    expect(src).toMatch(/\{!error && \(\s*<Button\s*variant="unstyled"\s*type="button"\s*onClick=\{exportPdf\}/)
    expect(src).toMatch(/setError\(e\.message \|\| 'Failed to load findings'\)/)
    expect(src).not.toMatch(/setFindings\(\[\]\)/)
    expect(src).toMatch(/<div hidden=\{!!error\}>\n {10}<HealTrendSparkline/)
  })
})
