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
    expect(src).toMatch(/const exportCsv = useCallback\(\(\) => \{\n {4}if \(queueUnavailable\) return/)
    expect(src).toMatch(/const exportPdf = useCallback\(\(\) => \{\n {4}if \(queueUnavailable\) return/)
    expect(src).toMatch(/exportDisabled=\{queueUnavailable \|\| !filteredItems\.length\}/)
    expect(src).toMatch(/\{!queueUnavailable && \(/)
    expect(src).not.toMatch(/setItems\(\[\]\)/)
  })

  it('mutes leftover leftover-GET Export CSV after a failed queue GET', () => {
    expect(src).toMatch(/api\.get\(`\/api\/self-improve\/queue\$\{qs\}`\)/)
    expect(src).toMatch(/onExport=\{queueUnavailable \? undefined : exportCsv\}/)
    expect(src).toMatch(/onRefresh=\{handleRefresh\}/)
    expect(src).toMatch(/setQueueUnavailable\(true\)/)
    expect(src).toMatch(/setQueueUnavailable\(false\)/)
    expect(src).toMatch(/setError\(e\?\.message \|\| 'Toggle failed'\)/)
    expect(src).toMatch(/setError\(e\?\.message \|\| 'Run failed'\)/)
    expect(src).not.toMatch(/Toggle failed[\s\S]{0,80}setQueueUnavailable/)
    expect(src).not.toMatch(/Run failed[\s\S]{0,80}setQueueUnavailable/)
    expect(src).not.toMatch(/setItems\(\[\]\)/)
  })

  it('mutes leftover leftover-engine Power control after a failed status GET', () => {
    expect(src).toMatch(/disabled=\{busy \|\| !!error\}/)
    expect(src).toMatch(/error \? 'Status unconfirmed' : enabled \? 'Enabled — click to disable'/)
    expect(src).toMatch(/setError\(e\?\.message \|\| 'Failed to load'\)/)
    expect(src).not.toMatch(/setError\(e\?\.message \|\| 'Failed to load'\)\s*setStatus\(null\)/)
  })
})
