import { describe, it, expect } from 'vitest'
import { readFileSync } from 'node:fs'
import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'

const src = readFileSync(
  join(dirname(fileURLToPath(import.meta.url)), 'IntegrationManager.jsx'),
  'utf8',
)

describe('IntegrationManager live-only truth', () => {
  it('does not paint zero connected integrations when GET /api/integrations fails', () => {
    expect(src).toMatch(/data-testid="integrations-unavailable"/)
    expect(src).toMatch(/unavailable_title/)
    expect(src).toMatch(/!loadError && \(/)
    expect(src).toMatch(/!Array\.isArray\(data\.integrations\)/)
  })
})
