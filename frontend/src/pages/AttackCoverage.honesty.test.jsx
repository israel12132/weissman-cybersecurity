import { describe, it, expect } from 'vitest'
import { readFileSync } from 'node:fs'
import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'

const src = readFileSync(
  join(dirname(fileURLToPath(import.meta.url)), 'AttackCoverage.jsx'),
  'utf8',
)

describe('AttackCoverage live-only truth', () => {
  it('does not dump leftover leftover-coverage CSV after a failed coverage GET', () => {
    expect(src).toMatch(/const handleExportCsv = useCallback\(\(\) => \{\n    if \(error\) return/)
    expect(src).toMatch(/exportDisabled=\{\!\!error \|\| !tactics\.length\}/)
    expect(src).toMatch(/badge=\{error \? 'MITRE ATT&CK' : \(data\?\.framework \|\| 'MITRE ATT&CK'\)\}/)
    expect(src).not.toMatch(/setData\(null\)/)
  })
})
