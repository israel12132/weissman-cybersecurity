import { describe, it, expect } from 'vitest'
import { readFileSync } from 'node:fs'
import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'

const src = readFileSync(
  join(dirname(fileURLToPath(import.meta.url)), 'WhiteLabelBrand.jsx'),
  'utf8',
)

describe('WhiteLabelBrand live-only truth', () => {
  it('does not dump leftover leftover-brand CSV after a failed brand GET', () => {
    expect(src).toMatch(/const exportCsv = useCallback\(\(\) => \{\n    if \(error\) return/)
    expect(src).toMatch(/exportDisabled=\{\!\!error \|\| !rows\.length\}/)
    expect(src).toMatch(/\{\!error && \(/)
    expect(src).toMatch(/\} catch \(e\) \{\n      setError/)
    expect(src).not.toMatch(/\} catch \(e\) \{\n      setRaw\(/)
  })
})
