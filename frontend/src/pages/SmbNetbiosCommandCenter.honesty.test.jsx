import { describe, it, expect } from 'vitest'
import { readFileSync } from 'node:fs'
import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'

const src = readFileSync(
  join(dirname(fileURLToPath(import.meta.url)), 'SmbNetbiosCommandCenter.jsx'),
  'utf8',
)

describe('SmbNetbiosCommandCenter live-only truth', () => {
  it('does not paint runToPopulate when GET /api/engines/history fails', () => {
    expect(src).toMatch(/data-testid="smb-netbios-history-unavailable"/)
    expect(src).toMatch(/historyUnavailable/)
    expect(src).toMatch(/unavailable=\{historyUnavailable\}/)
    expect(src).toMatch(/!historyUnavailable/)
  })

  it('does not paint leftover leftover-posture or leftover leftover-paths after a failed history GET', () => {
    expect(src).toMatch(/\(summary \|\| findings\.length > 0\) && !historyUnavailable/)
    expect(src).toMatch(/!historyUnavailable && attackPaths\.length > 0/)
    expect(src).not.toMatch(/posture_score \?\? ev\.posture_score \?\? 0/)
    expect(src).not.toMatch(/ransomware_readiness \?\? 0/)
    expect(src).toMatch(/if \(historyUnavailable\) return/)
    expect(src).toMatch(/!historyUnavailable && findings\.length > 0/)
  })
})
