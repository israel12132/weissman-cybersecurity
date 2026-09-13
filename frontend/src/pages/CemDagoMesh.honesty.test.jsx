import { describe, it, expect } from 'vitest'
import { readFileSync } from 'node:fs'
import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'

const src = readFileSync(
  join(dirname(fileURLToPath(import.meta.url)), 'CemDagoMesh.jsx'),
  'utf8',
)

describe('CemDagoMesh live-only truth', () => {
  it('does not paint no_waves when CEM-DAGO mesh load fails', () => {
    expect(src).toMatch(/data-testid="cem-dago-unavailable"/)
    expect(src).toMatch(/unavailable_title/)
    expect(src).toMatch(/!Array\.isArray\(man\?\.manifests\) \|\| !Array\.isArray\(wv\?\.waves\)/)
    expect(src).not.toMatch(/setWaves\(Array\.isArray\(wv\?\.waves\) \? wv\.waves : \[\]\)/)
  })

  it('does not dump leftover leftover-blackboard CSV after a failed mesh GET', () => {
    expect(src).toMatch(/const handleExportCsv = useCallback\(\(\) => \{\n    if \(error\) return/)
    expect(src).toMatch(/exportDisabled=\{\!\!error \|\| !evidenceRows\.length\}/)
  })
})
