import { describe, it, expect } from 'vitest'
import { readFileSync } from 'node:fs'
import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'

const src = readFileSync(
  join(dirname(fileURLToPath(import.meta.url)), 'SupremeBrain.jsx'),
  'utf8',
)

describe('SupremeBrain live-only truth', () => {
  it('does not dump leftover leftover-brain JSON after a failed supreme-brain GET', () => {
    expect(src).toMatch(/const handleExportJson = useCallback\(\(\) => \{\n    if \(error\) return/)
    expect(src).toMatch(/exportDisabled=\{\!\!error \|\| !payload\}/)
    expect(src).toMatch(/\} catch \(e\) \{\n        setError/)
    expect(src).not.toMatch(/\} catch \(e\) \{\n        setPayload\(null\)/)
  })
})
