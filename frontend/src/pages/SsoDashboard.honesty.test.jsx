import { describe, it, expect } from 'vitest'
import { readFileSync } from 'node:fs'
import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'

const src = readFileSync(
  join(dirname(fileURLToPath(import.meta.url)), 'SsoDashboard.jsx'),
  'utf8',
)

describe('SsoDashboard live-only truth', () => {
  it('does not paint no-IdPs when the directory store is down', () => {
    expect(src).toMatch(/setIdpsUnavailable\(true\)/)
    expect(src).toMatch(/data-testid="sso-idps-unavailable"/)
    expect(src).toMatch(/!idpsUnavailable && idps\.length === 0/)
  })
})
