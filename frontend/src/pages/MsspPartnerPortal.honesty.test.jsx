import { describe, it, expect } from 'vitest'
import { readFileSync } from 'node:fs'
import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'

const src = readFileSync(
  join(dirname(fileURLToPath(import.meta.url)), 'MsspPartnerPortal.jsx'),
  'utf8',
)

describe('MsspPartnerPortal live-only truth', () => {
  it('does not paint a clean fleet when portfolio GET fails', () => {
    expect(src).toMatch(/apiFetch\('\/api\/portfolio\/posture'\)/)
    expect(src).toMatch(/error \? \(\n {8}<EmptyState title=\{t\(`\$\{NS\}\.load_failed`\)\} body=\{error\} \/>/)
    expect(src).toMatch(/empty_title/)
  })

  it('does not dump leftover leftover-portfolio CSV after a failed posture GET', () => {
    expect(src).toMatch(/const exportCsv = useCallback\(\(\) => \{\n {4}if \(error\) return/)
    expect(src).toMatch(/exportDisabled=\{!!error \|\| !filtered\.length\}/)
  })

  it('mutes leftover leftover-GET Export CSV after a failed posture GET', () => {
    expect(src).toMatch(/apiFetch\('\/api\/portfolio\/posture'\)/)
    expect(src).toMatch(/const exportCsv = useCallback\(\(\) => \{\n {4}if \(error\) return/)
    expect(src).toMatch(/onExport=\{error \? undefined : exportCsv\}/)
    expect(src).toMatch(/exportDisabled=\{!!error \|\| !filtered\.length\}/)
    expect(src).toMatch(/onRefresh=\{load\}/)
    expect(src).toMatch(/\} catch \(e\) \{\n {6}setError\(e\.message \|\| t\(`\$\{NS\}\.load_failed`\)\)\n {6}setData\(null\)/)
  })
})
