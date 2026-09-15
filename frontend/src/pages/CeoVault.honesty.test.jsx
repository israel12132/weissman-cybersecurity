import { describe, it, expect } from 'vitest'
import { readFileSync } from 'node:fs'
import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'

const src = readFileSync(
  join(dirname(fileURLToPath(import.meta.url)), 'CeoVault.jsx'),
  'utf8',
)

describe('CeoVault live-only truth', () => {
  it('does not paint an empty vault when GET /api/ceo/vault/secrets fails', () => {
    expect(src).toMatch(/data-testid="ceo-vault-unavailable"/)
    expect(src).toMatch(/unavailable_title/)
    expect(src).toMatch(/!Array\.isArray\(data\.secrets\)/)
    expect(src).toMatch(/setLoadError\(true\)/)
    expect(src).toMatch(/loadError \? null : secrets\.length === 0/)
    expect(src).not.toMatch(/setSecrets\(data\.secrets \|\| \[\]\)/)
  })

  it('does not paint leftover leftover-secret counts after a failed vault GET', () => {
    expect(src).toMatch(/resultCount=\{loadError \? undefined : visibleSecrets\.length\}/)
    expect(src).toMatch(/const handleExportCsv = useCallback\(\(\) => \{\n    if \(loadError\) return/)
    expect(src).toMatch(/exportDisabled=\{loadError \|\| !filteredFindings\.length\}/)
  })

  it('mutes leftover leftover-edit secret modal after a failed vault GET', () => {
    expect(src).toMatch(/\{\(createModal \|\| \(editModal && !loadError\)\) && \(/)
    expect(src).toMatch(/setLoadError\(true\);\n      toast\.error\(t\('pages\.ceoVault\.load_failed'\)\)/)
    expect(src).not.toMatch(/setLoadError\(true\);\n      setEditModal/)
  })

  it('mutes leftover leftover-GET Export CSV after a failed vault GET', () => {
    expect(src).toMatch(/api\.get\('\/api\/ceo\/vault\/secrets'\)/)
    expect(src).toMatch(/const handleExportCsv = useCallback\(\(\) => \{\n    if \(loadError\) return/)
    expect(src).toMatch(/onExport=\{loadError \? undefined : handleExportCsv\}/)
    expect(src).toMatch(/exportDisabled=\{loadError \|\| !filteredFindings\.length\}/)
    expect(src).toMatch(/onRefresh=\{fetchSecrets\}/)
    expect(src).toMatch(/toast\.error\(t\('pages\.ceoVault\.delete_failed'\)\)/)
    expect(src).not.toMatch(/delete_failed[\s\S]{0,80}setLoadError/)
    expect(src).not.toMatch(/Failed to fetch secrets:[\s\S]{0,80}setSecrets\(\[\]\)/)
  })
})
