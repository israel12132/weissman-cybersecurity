import { describe, it, expect } from 'vitest'
import { readFileSync } from 'node:fs'
import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'

const src = readFileSync(
  join(dirname(fileURLToPath(import.meta.url)), 'SystemConfiguration.jsx'),
  'utf8',
)

describe('SystemConfiguration live-only truth', () => {
  it('does not dump leftover leftover-config CSV after a failed config GET', () => {
    expect(src).toMatch(/configUnavailable/)
    expect(src).toMatch(/const handleExportCsv = useCallback\(\(\) => \{\n    if \(configUnavailable\) return/)
    expect(src).toMatch(/exportDisabled=\{configUnavailable \|\| !filteredFindings\.length\}/)
  })
})
