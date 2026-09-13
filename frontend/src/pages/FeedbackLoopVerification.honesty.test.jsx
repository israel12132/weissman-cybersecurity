import { describe, it, expect } from 'vitest'
import { readFileSync } from 'node:fs'
import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'

const src = readFileSync(
  join(dirname(fileURLToPath(import.meta.url)), 'FeedbackLoopVerification.jsx'),
  'utf8',
)

describe('FeedbackLoopVerification live-only truth', () => {
  it('does not paint a fake template option when the catalog is unconfirmed', () => {
    expect(src).toMatch(/data-testid="feedback-loop-templates-unavailable"/)
    expect(src).toMatch(/templatesUnavailable/)
    expect(src).toMatch(/templates_unavailable/)
    expect(src).not.toMatch(/<option value=\{DEFAULT_TEMPLATE\}>\{DEFAULT_TEMPLATE\}<\/option>/)
    expect(src).toMatch(/!selectedId \|\| templatesUnavailable/)
  })
})
