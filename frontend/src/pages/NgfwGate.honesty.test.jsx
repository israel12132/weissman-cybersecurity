import { describe, it, expect } from 'vitest'
import { readFileSync } from 'node:fs'
import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'

const src = readFileSync(
  join(dirname(fileURLToPath(import.meta.url)), 'NgfwGate.jsx'),
  'utf8',
)

describe('NgfwGate live-only truth', () => {
  it('does not dump leftover leftover-gate CSV after a failed vNGFW GET', () => {
    expect(src).toMatch(/const exportCsv = useCallback\(\(\) => \{\n    if \(error\) return/)
    expect(src).toMatch(/exportDisabled=\{\!\!error \|\| !filtered\.length\}/)
    expect(src).not.toMatch(/setFindings\(\[\]\)/)
  })
})
