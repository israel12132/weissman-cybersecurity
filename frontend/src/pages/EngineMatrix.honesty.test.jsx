import { describe, it, expect } from 'vitest'
import { readFileSync } from 'node:fs'
import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'

const src = readFileSync(
  join(dirname(fileURLToPath(import.meta.url)), 'EngineMatrix.jsx'),
  'utf8',
)

describe('EngineMatrix live-only truth', () => {
  it('does not paint idle last-run history when history-summary is unconfirmed', () => {
    expect(src).toMatch(/historyKnown=\{!historyUnavailable\}/)
    expect(src).toMatch(/state\.status \?\? \(historyKnown \? 'idle' : null\)/)
    expect(src).toMatch(/historyKnown\s*\?\s*t\('engines\.never_run'\)\s*:\s*'—'/)
    expect(src).toMatch(/known \?\? \{ color: '#6b7280'/)
    expect(src).not.toMatch(/map\[status\] \?\? map\.idle/)
  })
})
