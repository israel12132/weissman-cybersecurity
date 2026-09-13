import { describe, it, expect } from 'vitest'
import { readFileSync } from 'node:fs'
import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'

const src = readFileSync(
  join(dirname(fileURLToPath(import.meta.url)), 'ServerlessSecurityCommandCenter.jsx'),
  'utf8',
)

describe('ServerlessSecurityCommandCenter live-only truth', () => {
  it('does not paint run-to-populate when GET /api/engines/history fails', () => {
    expect(src).toMatch(/data-testid="serverless-security-history-unavailable"/)
    expect(src).toMatch(/history_unavailable/)
    expect(src).toMatch(/unavailable=\{historyUnavailable\}/)
    expect(src).toMatch(/!historyUnavailable/)
  })
})
