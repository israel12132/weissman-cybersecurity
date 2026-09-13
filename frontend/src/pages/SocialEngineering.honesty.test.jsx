import { describe, it, expect } from 'vitest'
import { readFileSync } from 'node:fs'
import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'

const src = readFileSync(
  join(dirname(fileURLToPath(import.meta.url)), 'SocialEngineering.jsx'),
  'utf8',
)

describe('SocialEngineering live-only truth', () => {
  it('does not paint zero campaigns when assessments or clients are unconfirmed', () => {
    expect(src).toMatch(/data-testid="social-engineering-unavailable"/)
    expect(src).toMatch(/data-testid="social-engineering-clients-unavailable"/)
    expect(src).toMatch(/unavailable_title/)
    expect(src).toMatch(/loading \|\| error \? '—'/)
    expect(src).toMatch(/!error && \(/)
    expect(src).not.toMatch(/\.catch\(\(\) => \{\}\)/)
  })
})
