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
    expect(src).toMatch(/setHistoryUnavailable\] = useState\(true\)/)
    expect(src).toMatch(/state\.status \?\? \(historyKnown \? 'idle' : null\)/)
    expect(src).toMatch(/historyKnown\s*\?\s*t\('engines\.never_run'\)\s*:\s*'—'/)
    expect(src).toMatch(/known \?\? \{ color: '#6b7280'/)
    expect(src).not.toMatch(/map\[status\] \?\? map\.idle/)
  })

  it('does not paint leftover leftover-findings-delta after a failed history-summary GET', () => {
    expect(src).toMatch(/historyKnown && findingsDelta > 0/)
  })

  it('does not paint leftover leftover-last-run after a failed history-summary GET', () => {
    expect(src).toMatch(/\(\(historyKnown && lastRun\) \|\| lastRun === 'just now'\)/)
    expect(src).toMatch(/historyKnown\s*\?\s*t\('engines\.never_run'\)\s*:\s*'—'/)
  })

  it('does not paint zero enabled engines when client config cannot be confirmed', () => {
    expect(src).toMatch(/data-testid="engine-matrix-config-unavailable"/)
    expect(src).toMatch(/config_unavailable/)
    expect(src).toMatch(/setConfigUnavailable\(true\)/)
    expect(src).toMatch(/data-testid="engine-matrix-integrations-unavailable"/)
    expect(src).not.toMatch(/apiFetch\(`\/api\/clients\/\$\{selectedClientId\}\/config`\)\.catch\(\(\) => null\)/)
  })
})
