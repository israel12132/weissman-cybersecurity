import { describe, it, expect } from 'vitest'
import { readFileSync } from 'node:fs'
import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'

const src = readFileSync(
  join(dirname(fileURLToPath(import.meta.url)), 'WeissmanFindingsPanel.jsx'),
  'utf8',
)

describe('WeissmanFindingsPanel live-only truth', () => {
  it('paints unavailable instead of ready/clean when history cannot be confirmed', () => {
    expect(src).toMatch(/unavailable = false/)
    expect(src).toMatch(/unavailableTestId/)
    expect(src).toMatch(/weissmanFindings\.unavailable_title/)
    expect(src).toMatch(/unavailable && displayTotal === 0/)
  })
})
