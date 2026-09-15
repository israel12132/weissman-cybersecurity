import { describe, it, expect } from 'vitest'
import { readFileSync } from 'node:fs'
import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'

const src = readFileSync(
  join(dirname(fileURLToPath(import.meta.url)), 'EndpointEdr.jsx'),
  'utf8',
)

describe('EndpointEdr live-only truth', () => {
  it('does not dump leftover leftover-agents CSV after a failed EDR GET', () => {
    expect(src).toMatch(/const exportCsv = useCallback\(\(\) => \{\n    if \(error\) return/)
    expect(src).toMatch(/exportDisabled=\{\!\!error \|\| !filtered\.length\}/)
    expect(src).not.toMatch(/setAgents\(\[\]\)/)
  })

  it('mutes leftover leftover-GET Export CSV after a failed EDR GET', () => {
    expect(src).toMatch(/apiFetch\('\/api\/agents\/status'\)/)
    expect(src).toMatch(/apiFetch\('\/api\/findings\?limit=300'\)/)
    expect(src).toMatch(/onExport=\{error \? undefined : exportCsv\}/)
    expect(src).toMatch(/setError\(e\.message \|\| t\(`\$\{NS\}\.load_failed`\)\)/)
    expect(src).not.toMatch(/setAgents\(\[\]\)/)
    expect(src).not.toMatch(/setFindings\(\[\]\)/)
  })
})
