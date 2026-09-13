import { describe, it, expect } from 'vitest'
import { readFileSync } from 'node:fs'
import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'

const src = readFileSync(
  join(dirname(fileURLToPath(import.meta.url)), 'SovereignDefenseMatrix.jsx'),
  'utf8',
)

describe('SovereignDefenseMatrix live-only truth', () => {
  it('does not paint an empty tenant picker when GET /api/clients fails', () => {
    expect(src).toMatch(/data-testid="sovereign-defense-clients-unavailable"/)
    expect(src).toMatch(/clients_unavailable/)
    expect(src).toMatch(/setClientsUnavailable\(true\)/)
    expect(src).not.toMatch(/\.catch\(\(\) => \{\}\)/)
  })

  it('does not paint a quiet-empty poison library when the feed fails', () => {
    expect(src).toMatch(/data-testid="sovereign-defense-poison-unavailable"/)
    expect(src).toMatch(/poison_unavailable/)
    expect(src).toMatch(/setPoisonLibUnavailable\(true\)/)
    expect(src).not.toMatch(/apiFetch\('\/api\/sovereign-defense\/poison-library'\)\.catch\(\(\) => null\)/)
  })

  it('does not hide chronos or cognitive trails when allSettled rejects', () => {
    expect(src).toMatch(/data-testid="sovereign-defense-chronos-unavailable"/)
    expect(src).toMatch(/data-testid="sovereign-defense-cognitive-unavailable"/)
    expect(src).toMatch(/setChronosUnavailable\(true\)/)
    expect(src).toMatch(/setCognitiveUnavailable\(true\)/)
  })

  it('does not paint configure-and-run when GET /api/engines/history fails', () => {
    expect(src).toMatch(/data-testid="sovereign-defense-history-unavailable"/)
    expect(src).toMatch(/history_unavailable/)
    expect(src).toMatch(/unavailable=\{historyUnavailable\}/)
  })
})
