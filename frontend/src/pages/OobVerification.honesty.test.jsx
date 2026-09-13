import { describe, it, expect } from 'vitest'
import { readFileSync } from 'node:fs'
import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'

const src = readFileSync(
  join(dirname(fileURLToPath(import.meta.url)), 'OobVerification.jsx'),
  'utf8',
)

describe('OobVerification live-only truth', () => {
  it('does not paint an empty callback trail when GET /api/oast/callbacks fails', () => {
    expect(src).toMatch(/data-testid="oob-callbacks-unavailable"/)
    expect(src).toMatch(/callbacks_unavailable/)
    expect(src).toMatch(/setCallbacksUnavailable\(true\)/)
    expect(src).not.toMatch(/apiFetch\('\/api\/oast\/callbacks'\)\.catch\(\(\) => null\)/)
  })
})
