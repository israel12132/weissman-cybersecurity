import { describe, it, expect } from 'vitest'
import { readFileSync } from 'node:fs'
import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'

const src = readFileSync(
  join(dirname(fileURLToPath(import.meta.url)), 'TemplateEngineWorkbench.jsx'),
  'utf8',
)

describe('TemplateEngineWorkbench live-only truth', () => {
  it('does not paint a fake http_baseline row when the catalog is unconfirmed', () => {
    expect(src).toMatch(/data-testid="template-engine-templates-unavailable"/)
    expect(src).toMatch(/templatesUnavailable/)
    expect(src).toMatch(/templates_unavailable/)
    expect(src).not.toMatch(/option value="http_baseline"/)
    expect(src).not.toMatch(/useState\('http_baseline'\)/)
  })

  it('does not dump leftover leftover-templates after a failed catalog GET', () => {
    expect(src).toMatch(/templates\.length > 0 && !templatesUnavailable && \(/)
    expect(src).toMatch(/const handleExportCsv = useCallback\(\(\) => \{\n    if \(templatesUnavailable\) return/)
    expect(src).toMatch(/exportDisabled=\{templatesUnavailable \|\| !filteredFindings\.length\}/)
  })
})
