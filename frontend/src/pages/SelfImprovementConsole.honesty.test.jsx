import { describe, it, expect } from 'vitest'
import { readFileSync } from 'node:fs'
import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'

const src = readFileSync(
  join(dirname(fileURLToPath(import.meta.url)), 'SelfImprovementConsole.jsx'),
  'utf8',
)

describe('SelfImprovementConsole live-only truth', () => {
  it('does not paint KPI zeros or no-proposals when status/queue load fails', () => {
    expect(src).toMatch(/data-testid="self-improvement-unavailable"/)
    expect(src).toMatch(/!Array\.isArray\(q\?\.items\)/)
    expect(src).toMatch(/error \? \(/)
    expect(src).not.toMatch(/setItems\(Array\.isArray\(q\?\.items\) \? q\.items : \[\]\)/)
  })
})
