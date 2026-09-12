import { describe, it, expect } from 'vitest'
import { readFileSync } from 'node:fs'
import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'

const src = readFileSync(
  join(dirname(fileURLToPath(import.meta.url)), 'CeoIntegratedCommandDeck.jsx'),
  'utf8',
)

describe('CeoIntegratedCommandDeck live-only truth', () => {
  it('does not paint safe-mode OFF or zero jobs when telemetry fields are null', () => {
    expect(src).not.toMatch(/const globalSafe = !!tel\?\.global_safe_mode/)
    expect(src).toMatch(/typeof tel\?\.global_safe_mode === 'boolean'/)
    expect(src).not.toMatch(/tenant_jobs_running \?\? 0/)
    expect(src).toMatch(/safeModeUnknown/)
  })
})
