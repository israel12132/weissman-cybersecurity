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
    expect(src).toMatch(/const exportCsv = useCallback\(\(\) => \{\n {4}if \(error\) return/)
    expect(src).toMatch(/exportDisabled=\{!!error \|\| !rows\.length\}/)
    expect(src).toMatch(/\{!error && \(/)
    expect(src).toMatch(/\} catch \(e\) \{\n {6}setError/)
    expect(src).not.toMatch(/\} catch \(e\) \{\n {6}setRaw\(/)
  })

  it('mutes leftover leftover-GET Export CSV after a failed brand GET', () => {
    expect(src).toMatch(/apiFetch\('\/api\/tenant\/brand'\)/)
    expect(src).toMatch(/onExport=\{error \? undefined : exportCsv\}/)
    expect(src).toMatch(/onRefresh=\{load\}/)
    expect(src).toMatch(/data-testid="white-label-brand-unavailable"/)
    expect(src).toMatch(/method: 'PUT'/)
    expect(src).toMatch(/toast\.error\(e\.message \|\| t\(`\$\{NS\}\.save_failed`\)\)/)
    expect(src).not.toMatch(/save_failed[\s\S]{0,80}setError/)
    expect(src).not.toMatch(/\} catch \(e\) \{\n {6}setRaw\(/)
  })
})
