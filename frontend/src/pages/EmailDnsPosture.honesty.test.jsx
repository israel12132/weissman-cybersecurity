import { describe, it, expect } from 'vitest'
import { readFileSync } from 'node:fs'
import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'

const src = readFileSync(
  join(dirname(fileURLToPath(import.meta.url)), 'EmailDnsPosture.jsx'),
  'utf8',
)

describe('EmailDnsPosture live-only truth', () => {
  it('does not paint appears-strong when GET /api/engines/history fails', () => {
    expect(src).toMatch(/data-testid="email-dns-history-unavailable"/)
    expect(src).toMatch(/history_unavailable/)
    expect(src).toMatch(/historyUnavailable/)
    expect(src).toMatch(/!historyUnavailable/)
  })
})
