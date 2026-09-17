import { describe, it, expect } from 'vitest'
import { readFileSync } from 'node:fs'
import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'

const src = readFileSync(
  join(dirname(fileURLToPath(import.meta.url)), 'SoarHitlQueue.jsx'),
  'utf8',
)

describe('SoarHitlQueue live-only truth', () => {
  it('does not paint an idle empty HITL queue when executions fetch fails', () => {
    expect(src).toMatch(/data-testid="soar-hitl-unavailable"/)
    expect(src).toMatch(/unavailable_title/)
    expect(src).toMatch(/!unavailable && !fetchLoading && filteredItems\.length === 0/)
  })

  it('mutes leftover leftover-GET Export CSV after a failed executions GET', () => {
    expect(src).toMatch(/apiFetch\(`\/api\/soar\/executions\?status=\$\{encodeURIComponent\(activeTab\)\}`\)/)
    expect(src).toMatch(/const handleExportCsv = useCallback\(\(\) => \{\n {4}if \(unavailable\) return\n {4}exportQueueCsv\(filteredItems\)/)
    expect(src).toMatch(/onExport=\{unavailable \? undefined : handleExportCsv\}/)
    expect(src).toMatch(/exportDisabled=\{unavailable \|\| !filteredFindings\.length\}/)
    expect(src).toMatch(/onRefresh=\{fetchQueue\}/)
    expect(src).toMatch(/unavailable && !fetchLoading && !hasLoadedRef\.current/)
    expect(src).toMatch(/setUnavailable\(true\)/)
    expect(src).not.toMatch(/if \(!hasLoadedRef\.current\) setUnavailable\(true\)/)
    expect(src).not.toMatch(/approval_failed[\s\S]{0,160}setUnavailable/)
    expect(src).not.toMatch(/deny_failed[\s\S]{0,160}setUnavailable/)
  })

  it('mutes leftover leftover-GET pendingCount badge after a failed executions GET', () => {
    expect(src).toMatch(/badge=\{!unavailable && typeof pendingCount === 'number' && pendingCount > 0 \? t\('pages\.soarHitlQueue\.pending_badge', \{ count: pendingCount \}\) : undefined\}/)
    expect(src).toMatch(/setUnavailable\(true\)/)
    expect(src).not.toMatch(/setPendingCount\(null\)/)
    expect(src).not.toMatch(/setItems\(\[\]\)/)
    expect(src).not.toMatch(/approval_failed[\s\S]{0,160}setUnavailable/)
    expect(src).not.toMatch(/deny_failed[\s\S]{0,160}setUnavailable/)
  })
})
