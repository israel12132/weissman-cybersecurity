import { describe, it, expect } from 'vitest'
import { readFileSync } from 'node:fs'
import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'

const src = readFileSync(
  join(dirname(fileURLToPath(import.meta.url)), 'ContainmentRulesBuilder.jsx'),
  'utf8',
)

describe('ContainmentRulesBuilder live-only truth', () => {
  it('does not paint zero containment rules when the store or clients list is unconfirmed', () => {
    expect(src).toMatch(/data-testid="containment-rules-unavailable"/)
    expect(src).toMatch(/unavailable_title/)
    expect(src).toMatch(/clientsUnavailable/)
    expect(src).toMatch(/if \(clientsUnavailable\) \{\s*setUnavailable\(true\);/)
    expect(src).toMatch(/!unavailable && \(/)
  })
})
