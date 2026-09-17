import { describe, it, expect } from 'vitest'
import { readFileSync } from 'node:fs'
import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'

const src = readFileSync(
  join(dirname(fileURLToPath(import.meta.url)), 'SovereignTheater.jsx'),
  'utf8',
)

describe('SovereignTheater live-only truth', () => {
  it('does not dump leftover leftover-operator JSON after a failed refresh GET', () => {
    expect(src).toMatch(/const handleExport = useCallback\(async \(\) => \{\n {4}if \(error\) return/)
    expect(src).toMatch(/exportDisabled=\{!!error \|\| exporting\}/)
    expect(src).toMatch(/!error && knowledge\?\.production_engine_count != null/)
    expect(src).toMatch(/\} catch \(e\) \{\n {6}setError\(e\.message \|\| t\(`\$\{NS\}\.load_failed`\)\)/)
  })
})
