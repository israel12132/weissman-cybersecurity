import { describe, it, expect } from 'vitest'
import { readFileSync } from 'node:fs'
import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'

const src = readFileSync(
  join(dirname(fileURLToPath(import.meta.url)), 'CouncilHitlQueue.jsx'),
  'utf8',
)

describe('CouncilHitlQueue live-only truth', () => {
  it('does not paint an idle council queue when GET /api/council/hitl/queue is unconfirmed', () => {
    expect(src).toMatch(/data-testid="council-hitl-unavailable"/)
    expect(src).toMatch(/unavailable_title/)
    expect(src).toMatch(/!Array\.isArray\(data\.items\)/)
    expect(src).toMatch(/!unavailable && !fetchLoading && filteredItems\.length === 0/)
    expect(src).not.toMatch(/data\.items \?\? \[\]/)
  })

  it('mutes leftover leftover-GET Export CSV after a failed queue GET', () => {
    expect(src).toMatch(/api\.get\(`\/api\/council\/hitl\/queue\$\{qs\}`\)/)
    expect(src).toMatch(/const handleExportCsv = useCallback\(\(\) => \{\n    if \(unavailable\) return\n    exportQueueCsv\(filteredItems\)/)
    expect(src).toMatch(/onExport=\{unavailable \? undefined : handleExportCsv\}/)
    expect(src).toMatch(/exportDisabled=\{unavailable \|\| !filteredFindings\.length\}/)
    expect(src).toMatch(/onRefresh=\{fetchQueue\}/)
    expect(src).toMatch(/unavailable && !fetchLoading && !hasLoadedRef\.current/)
    expect(src).toMatch(/setUnavailable\(true\)/)
    expect(src).not.toMatch(/if \(!hasLoadedRef\.current\) setUnavailable\(true\)/)
    expect(src).not.toMatch(/setItems\(\[\]\)/)
    expect(src).not.toMatch(/approval_failed[\s\S]{0,160}setUnavailable/)
    expect(src).not.toMatch(/rejection_failed[\s\S]{0,160}setUnavailable/)
  })
})
