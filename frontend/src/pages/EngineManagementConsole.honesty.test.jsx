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

  it('mutes leftover leftover-config modal after a failed catalog GET', () => {
    expect(src).toMatch(/\{configModal && selectedEngine && !catalogUnavailable && \(/)
    expect(src).toMatch(/setCatalogUnavailable\(true\);\n      setEngines\(\[\]\)/)
    expect(src).not.toMatch(/setCatalogUnavailable\(true\);\n      setConfigModal/)
    expect(src).not.toMatch(/setCatalogUnavailable\(true\);\n      setSelectedEngine/)
  })
})
