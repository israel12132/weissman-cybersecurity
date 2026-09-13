import { describe, it, expect } from 'vitest'
import { readFileSync } from 'node:fs'
import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'

const src = readFileSync(
  join(dirname(fileURLToPath(import.meta.url)), 'JwtAttackLab.jsx'),
  'utf8',
)

describe('JwtAttackLab live-only truth', () => {
  it('does not paint ready-to-assess when GET /api/engines/history fails', () => {
    expect(src).toMatch(/data-testid="jwt-attack-lab-history-unavailable"/)
    expect(src).toMatch(/history_unavailable/)
    expect(src).toMatch(/setHistoryUnavailable\(true\)/)
    expect(src).toMatch(/classifyEngineHistory/)
    expect(src).toMatch(/!historyUnavailable &&/)
    expect(src).not.toMatch(/honest empty — no seeded history/)
  })
})
