import { describe, it, expect } from 'vitest'
import { readFileSync } from 'node:fs'
import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'

const src = readFileSync(
  join(dirname(fileURLToPath(import.meta.url)), 'ContainmentRulesBuilder.jsx'),
  'utf8',
)

describe('ContainmentRulesBuilder live-only truth', () => {
  it('does not paint zero containment rules when the store or clients list is unconfirmed', () => {
    expect(src).toMatch(/data-testid="containment-rules-unavailable"/)
    expect(src).toMatch(/unavailable_title/)
    expect(src).toMatch(/clientsUnavailable/)
    expect(src).toMatch(/if \(clientsUnavailable\) \{\s*setUnavailable\(true\);/)
    expect(src).toMatch(/!unavailable && \(/)
  })

  it('does not dump leftover leftover-rules CSV after a failed rules GET', () => {
    expect(src).toMatch(/const handleExportCsv = useCallback\(\(\) => \{\n    if \(unavailable\) return/)
    expect(src).toMatch(/exportDisabled=\{unavailable \|\| !filteredFindings\.length\}/)
  })

  it('mutes leftover leftover-edit containment modal after a failed rules GET', () => {
    expect(src).toMatch(/\{\(createModal \|\| \(editModal && !unavailable\)\) && \(/)
    expect(src).toMatch(/setUnavailable\(true\);\n    \} finally \{/)
    expect(src).not.toMatch(/setUnavailable\(true\);\n      setEditModal/)
  })

  it('mutes leftover leftover-GET Export CSV after a failed rules GET', () => {
    expect(src).toMatch(/api\.get\(withClientId\('\/api\/containment\/rules', cid\)\)/)
    expect(src).toMatch(/const handleExportCsv = useCallback\(\(\) => \{\n    if \(unavailable\) return/)
    expect(src).toMatch(/onExport=\{unavailable \? undefined : handleExportCsv\}/)
    expect(src).toMatch(/exportDisabled=\{unavailable \|\| !filteredFindings\.length\}/)
    expect(src).toMatch(/onRefresh=\{reloadRules\}/)
    expect(src).toMatch(/console\.error\('Failed to fetch containment rules:', error\);\n      setUnavailable\(true\);/)
    expect(src).not.toMatch(/Failed to fetch containment rules:[\s\S]{0,80}setRules\(\[\]\)/)
  })
})
