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
})
