import { describe, it, expect } from 'vitest'
import { readFileSync } from 'node:fs'
import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'

const src = readFileSync(
  join(dirname(fileURLToPath(import.meta.url)), 'SupremeNerveCenter.jsx'),
  'utf8',
)

describe('SupremeNerveCenter live-only truth', () => {
  it('does not paint running-now zeros without a confirmed snapshot', () => {
    expect(src).toMatch(/data-testid="supreme-nerve-unavailable"/)
    expect(src).toMatch(/unavailable_title/)
    expect(src).toMatch(/section === 'overview' && snap &&/)
    expect(src).not.toMatch(/value=\{summary\.engines_running \?\? 0\}/)
  })
})
