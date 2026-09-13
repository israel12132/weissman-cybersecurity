import { describe, it, expect } from 'vitest'
import { readFileSync } from 'node:fs'
import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'

const src = readFileSync(
  join(dirname(fileURLToPath(import.meta.url)), 'EngineManagementConsole.jsx'),
  'utf8',
)

describe('EngineManagementConsole live-only truth', () => {
  it('does not fall back to health active_engines as a live catalog', () => {
    expect(src).not.toMatch(/\/api\/health/)
    expect(src).toMatch(/data-testid="engine-catalog-unavailable"/)
    expect(src).toMatch(/unavailable_title/)
    expect(src).toMatch(/catalogUnavailable/)
  })
})
