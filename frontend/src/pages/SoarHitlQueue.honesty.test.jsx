import { describe, it, expect } from 'vitest'
import { readFileSync } from 'node:fs'
import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'

const src = readFileSync(
  join(dirname(fileURLToPath(import.meta.url)), 'SoarHitlQueue.jsx'),
  'utf8',
)

describe('SoarHitlQueue live-only truth', () => {
  it('does not paint an idle empty HITL queue when executions fetch fails', () => {
    expect(src).toMatch(/data-testid="soar-hitl-unavailable"/)
    expect(src).toMatch(/unavailable_title/)
    expect(src).toMatch(/!unavailable && !fetchLoading && filteredItems\.length === 0/)
  })
})
