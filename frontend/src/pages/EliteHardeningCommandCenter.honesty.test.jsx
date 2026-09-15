import { describe, it, expect } from 'vitest'
import { readFileSync } from 'node:fs'
import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'

const src = readFileSync(
  join(dirname(fileURLToPath(import.meta.url)), 'EliteHardeningCommandCenter.jsx'),
  'utf8',
)

describe('EliteHardeningCommandCenter live-only truth', () => {
  it('does not dump leftover leftover-controls CSV after a failed elite GET', () => {
    expect(src).toMatch(/const doExport = \(kind\) => \{\n    if \(error\) return/)
    expect(src).toMatch(/exportDisabled=\{\!\!error \|\| !filtered\.length\}/)
    expect(src).not.toMatch(/setData\(null\)/)
  })

  it('mutes leftover leftover-GET Export CSV after a failed elite-hardening GET', () => {
    expect(src).toMatch(/apiFetch\('\/api\/elite-hardening\/status'\)/)
    expect(src).toMatch(/onExport=\{error \? undefined : \(\) => doExport\('csv'\)\}/)
    expect(src).toMatch(/onRefresh=\{load\}/)
    expect(src).toMatch(/setError\(e\.message \|\| t\(`\$\{NS\}\.load_failed`\)\)/)
    expect(src).not.toMatch(/method: 'POST'/)
    expect(src).not.toMatch(/method: 'PATCH'/)
  })
})
