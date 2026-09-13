import { describe, it, expect } from 'vitest'
import { readFileSync } from 'node:fs'
import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'

const src = readFileSync(
  join(dirname(fileURLToPath(import.meta.url)), 'PasswordSprayCommandCenter.jsx'),
  'utf8',
)

describe('PasswordSprayCommandCenter live-only truth', () => {
  it('does not paint runToPopulate when GET /api/engines/history fails', () => {
    expect(src).toMatch(/data-testid="password-spray-history-unavailable"/)
    expect(src).toMatch(/historyUnavailable/)
    expect(src).toMatch(/unavailable=\{historyUnavailable\}/)
    expect(src).toMatch(/!historyUnavailable/)
  })

  it('does not paint leftover leftover-posture after a failed history GET', () => {
    expect(src).toMatch(/posture && !historyUnavailable/)
    expect(src).toMatch(/!historyUnavailable && paths\.length > 0/)
    expect(src).not.toMatch(/Number\(scores\[k\] \?\? 0\)/)
    expect(src).toMatch(/if \(historyUnavailable\) return/)
    expect(src).toMatch(/!historyUnavailable && findings\.length > 0/)
  })

  it('does not dump leftover leftover-findings CSV after a failed history GET', () => {
    expect(src).toMatch(/const handleExportCsv = useCallback\(\(\) => \{\n    if \(historyUnavailable\) return/)
    expect(src).toMatch(/exportDisabled=\{historyUnavailable \|\| !filteredFindings\.length\}/)
  })
})
