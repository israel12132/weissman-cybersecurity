import { describe, it, expect } from 'vitest'
import { readFileSync } from 'node:fs'
import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'

const src = readFileSync(
  join(dirname(fileURLToPath(import.meta.url)), 'ClientEngagements.jsx'),
  'utf8',
)

describe('ClientEngagements live-only truth', () => {
  it('does not dump leftover leftover-engagements CSV after a failed engagements GET', () => {
    expect(src).toMatch(/data-testid="engagements-empty-suppressed"/)
    expect(src).toMatch(/const handleExportCsv = useCallback\(\(\) => \{\n    if \(error\) return/)
    expect(src).toMatch(/exportDisabled=\{\!\!error \|\| !filteredFindings\.length\}/)
  })
})
