import { describe, it, expect } from 'vitest'
import { readFileSync } from 'node:fs'
import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'

const src = readFileSync(
  join(dirname(fileURLToPath(import.meta.url)), 'GodModeEngineMatrix.jsx'),
  'utf8',
)

describe('GodModeEngineMatrix live-only truth', () => {
  it('does not paint orchestrator idle when scanningActive is not a boolean', () => {
    expect(src).toMatch(/scanningActive === true/)
    expect(src).toMatch(/scanningActive === false/)
    expect(src).not.toMatch(/scanningActive\s*\?\s*t\('components\.ceo\.engineMatrix\.orchestratorScanning'\)/)
  })
})
