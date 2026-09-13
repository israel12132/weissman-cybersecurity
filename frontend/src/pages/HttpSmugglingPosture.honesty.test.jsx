import { describe, it, expect } from 'vitest'
import { readFileSync } from 'node:fs'
import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'

const src = readFileSync(
  join(dirname(fileURLToPath(import.meta.url)), 'HttpSmugglingPosture.jsx'),
  'utf8',
)

describe('HttpSmugglingPosture live-only truth', () => {
  it('does not paint appears-strong when GET /api/engines/history fails', () => {
    expect(src).toMatch(/data-testid="http-smuggling-history-unavailable"/)
    expect(src).toMatch(/history_unavailable/)
    expect(src).toMatch(/unavailable=\{historyUnavailable\}/)
    expect(src).toMatch(/!historyUnavailable/)
  })

  it('does not coerce missing posture to 100/A or paint leftover leftover-scorecards', () => {
    expect(src).toMatch(/findings\.length > 0 && !historyUnavailable/)
    expect(src).toMatch(/const hasScore = raw != null && Number\.isFinite\(Number\(raw\)\)/)
    expect(src).not.toMatch(/\?\? 100/)
    expect(src).not.toMatch(/\?\? 'A'/)
  })
})
