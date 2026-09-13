import { describe, it, expect } from 'vitest'
import { readFileSync } from 'node:fs'
import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'

const src = readFileSync(
  join(dirname(fileURLToPath(import.meta.url)), 'Clients.jsx'),
  'utf8',
)

describe('Clients live-only truth', () => {
  it('does not paint leftover leftover-last-updated after a failed clients GET', () => {
    expect(src).toMatch(/lastUpdated=\{error \? null : lastUpdated\}/)
    expect(src).toMatch(/count=\{error \? null : clients\.length\}/)
    expect(src).toMatch(/\) : !error && clients\.length > 0 \? \(/)
    expect(src).toMatch(/const handleExportCsv = useCallback\(\(\) => \{\n    if \(error\) return/)
    expect(src).toMatch(/exportDisabled=\{\!\!error \|\| !filteredFindings\.length\}/)
  })
})
