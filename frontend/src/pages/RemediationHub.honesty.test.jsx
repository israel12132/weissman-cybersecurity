import { describe, it, expect } from 'vitest'
import { readFileSync } from 'node:fs'
import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'

const src = readFileSync(
  join(dirname(fileURLToPath(import.meta.url)), 'RemediationHub.jsx'),
  'utf8',
)

describe('RemediationHub live-only truth', () => {
  it('does not paint pending-fix zeros when findings fetch fails', () => {
    expect(src).toMatch(/data-testid="remediation-hub-unavailable"/)
    expect(src).toMatch(/unavailable_title/)
    expect(src).toMatch(/loading=\{loading \|\| !!error\}/)
    expect(src).toMatch(/ok\.length !== list\.length/)
  })
})
