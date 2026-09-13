import { describe, it, expect } from 'vitest'
import { readFileSync } from 'node:fs'
import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'

const src = readFileSync(
  join(dirname(fileURLToPath(import.meta.url)), 'OobVerification.jsx'),
  'utf8',
)

describe('OobVerification live-only truth', () => {
  it('does not paint an empty callback trail when GET /api/oast/callbacks fails', () => {
    expect(src).toMatch(/data-testid="oob-callbacks-unavailable"/)
    expect(src).toMatch(/callbacks_unavailable/)
    expect(src).toMatch(/setCallbacksUnavailable\(true\)/)
    expect(src).not.toMatch(/apiFetch\('\/api\/oast\/callbacks'\)\.catch\(\(\) => null\)/)
  })

  it('does not dump leftover leftover-callbacks after a failed callbacks GET', () => {
    expect(src).toMatch(/callbacks\.length > 0 && !callbacksUnavailable && \(/)
    expect(src).toMatch(/!callbacksUnavailable && \(\s*<WeissmanListToolbar/)
    expect(src).toMatch(/const handleExportCsv = useCallback\(\(\) => \{\n    if \(callbacksUnavailable\) return/)
    expect(src).toMatch(/exportDisabled=\{callbacksUnavailable \|\| !filteredFindings\.length\}/)
    expect(src).toMatch(/setCallbacksUnavailable\(true\)\n      const body = e\?\.response/)
    expect(src).toMatch(/!callbacksUnavailable && \(\n                <div className="grid grid-cols-2 gap-3">/)
  })
})
