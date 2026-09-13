import { describe, it, expect } from 'vitest'
import { readFileSync } from 'node:fs'
import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'

const src = readFileSync(
  join(dirname(fileURLToPath(import.meta.url)), 'SelfImprovementConsole.jsx'),
  'utf8',
)

describe('SelfImprovementConsole live-only truth', () => {
  it('does not paint KPI zeros or no-proposals when status/queue load fails', () => {
    expect(src).toMatch(/data-testid="self-improvement-unavailable"/)
    expect(src).toMatch(/!Array\.isArray\(q\?\.items\)/)
    expect(src).toMatch(/error \? \(/)
    expect(src).not.toMatch(/setItems\(Array\.isArray\(q\?\.items\) \? q\.items : \[\]\)/)
  })

  it('does not dump leftover leftover-proposals CSV after a failed queue GET', () => {
    expect(src).toMatch(/const exportCsv = useCallback\(\(\) => \{\n    if \(error\) return/)
    expect(src).toMatch(/const exportPdf = useCallback\(\(\) => \{\n    if \(error\) return/)
    expect(src).toMatch(/exportDisabled=\{\!\!error \|\| !filteredItems\.length\}/)
    expect(src).toMatch(/disabled=\{\!\!error \|\| !filteredItems\.length\}/)
  })

  it('mutes leftover leftover-engine Power control after a failed status GET', () => {
    expect(src).toMatch(/disabled=\{busy \|\| !!error\}/)
    expect(src).toMatch(/error \? 'Status unconfirmed' : enabled \? 'Enabled — click to disable'/)
    expect(src).toMatch(/setError\(e\?\.message \|\| 'Failed to load'\)/)
    expect(src).not.toMatch(/setError\(e\?\.message \|\| 'Failed to load'\)\s*setStatus\(null\)/)
  })
})
