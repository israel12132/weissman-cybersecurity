import { describe, it, expect } from 'vitest'
import { readFileSync } from 'node:fs'
import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'

const src = readFileSync(
  join(dirname(fileURLToPath(import.meta.url)), 'ClientIntegrations.jsx'),
  'utf8',
)

describe('ClientIntegrations live-only truth', () => {
  it('does not paint a blank integrations form as unconfigured when load fails', () => {
    expect(src).toMatch(/data-testid="client-integrations-unavailable"/)
    expect(src).toMatch(/unavailable_title/)
    expect(src).toMatch(/disabled=\{saving \|\| unavailable\}/)
  })
})
