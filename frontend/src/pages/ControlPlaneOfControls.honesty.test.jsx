import { describe, it, expect } from 'vitest'
import { readFileSync } from 'node:fs'
import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'

const src = readFileSync(
  join(dirname(fileURLToPath(import.meta.url)), 'ControlPlaneOfControls.jsx'),
  'utf8',
)

describe('ControlPlaneOfControls live-only truth', () => {
  it('mutes leftover leftover-GET Export CSV after a failed findings GET', () => {
    expect(src).toMatch(/apiFetch\('\/api\/findings\?limit=500'/)
    expect(src).toMatch(/const exportCsv = useCallback\(\(\) => \{\n    if \(error\) return/)
    expect(src).toMatch(/onExport=\{error \? undefined : exportCsv\}/)
    expect(src).toMatch(/exportDisabled=\{\!\!error \|\| !filtered\.length\}/)
    expect(src).toMatch(/setError\(e\.message \|\| 'load failed'\)/)
    expect(src).toMatch(/setFindings\(\[\]\)\n      setError\(e\.message \|\| 'load failed'\)/)
  })
})
