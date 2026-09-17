import { describe, it, expect } from 'vitest'
import { readFileSync } from 'node:fs'
import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'

const src = readFileSync(
  join(dirname(fileURLToPath(import.meta.url)), 'ItdrCommandCenter.jsx'),
  'utf8',
)

describe('ItdrCommandCenter live-only truth', () => {
  it('does not dump leftover leftover-events CSV after a failed ITDR GET', () => {
    expect(src).toMatch(/const exportCsv = useCallback\(\(\) => \{\n {4}if \(error\) return/)
    expect(src).toMatch(/exportDisabled=\{!!error \|\| !filtered\.length\}/)
    expect(src).not.toMatch(/setEvents\(\[\]\)/)
  })

  it('mutes leftover leftover-GET Export CSV after a failed ITDR GET', () => {
    expect(src).toMatch(/apiFetch\('\/api\/itdr\/connectors'\)/)
    expect(src).toMatch(/apiFetch\('\/api\/itdr\/auth-events\?limit=500'\)/)
    expect(src).toMatch(/onExport=\{error \? undefined : exportCsv\}/)
    expect(src).toMatch(/setError\(err\.message \|\| t\(`\$\{NS\}\.load_failed`\)\)/)
    expect(src).not.toMatch(/catch \(err\) \{\s*setError\(err\.message \|\| t\(`\$\{NS\}\.load_failed`\)\)\s*setEvents/)
    expect(src).not.toMatch(/catch \(err\) \{\s*setError\(err\.message \|\| t\(`\$\{NS\}\.load_failed`\)\)\s*setConnectors/)
  })
})
