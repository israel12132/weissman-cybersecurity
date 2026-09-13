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
})
