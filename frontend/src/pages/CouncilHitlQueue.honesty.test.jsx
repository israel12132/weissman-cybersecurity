import { describe, it, expect } from 'vitest'
import { readFileSync } from 'node:fs'
import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'

const src = readFileSync(
  join(dirname(fileURLToPath(import.meta.url)), 'CouncilHitlQueue.jsx'),
  'utf8',
)

describe('CouncilHitlQueue live-only truth', () => {
  it('does not paint an idle council queue when GET /api/council/hitl/queue is unconfirmed', () => {
    expect(src).toMatch(/data-testid="council-hitl-unavailable"/)
    expect(src).toMatch(/unavailable_title/)
    expect(src).toMatch(/!Array\.isArray\(data\.items\)/)
    expect(src).toMatch(/!unavailable && !fetchLoading && filteredItems\.length === 0/)
    expect(src).not.toMatch(/data\.items \?\? \[\]/)
  })
})
