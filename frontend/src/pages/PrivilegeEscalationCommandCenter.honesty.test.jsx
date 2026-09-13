import { describe, it, expect } from 'vitest'
import { readFileSync } from 'node:fs'
import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'

const src = readFileSync(
  join(dirname(fileURLToPath(import.meta.url)), 'PrivilegeEscalationCommandCenter.jsx'),
  'utf8',
)

describe('PrivilegeEscalationCommandCenter live-only truth', () => {
  it('does not paint runToPopulate when GET /api/engines/history fails', () => {
    expect(src).toMatch(/data-testid="privilege-escalation-history-unavailable"/)
    expect(src).toMatch(/historyUnavailable/)
    expect(src).toMatch(/unavailable=\{historyUnavailable\}/)
    expect(src).toMatch(/!historyUnavailable/)
  })

  it('does not paint leftover leftover-posture above the unavailable banner', () => {
    expect(src).toMatch(/posture && !historyUnavailable/)
    expect(src).not.toMatch(/ev\.score \?\? 0/)
    expect(src).not.toMatch(/ds\.score \?\? 0/)
    expect(src).not.toMatch(/n \?\? 0/)
    expect(src).toMatch(/if \(historyUnavailable\) return/)
    expect(src).toMatch(/!historyUnavailable && findings\.length > 0/)
  })
})
