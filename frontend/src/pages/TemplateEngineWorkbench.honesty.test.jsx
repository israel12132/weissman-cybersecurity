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

  it('mutes leftover catalog select options after a failed templates GET', () => {
    expect(src).toMatch(/\(!templatesUnavailable \? visibleTemplates : \[\]\)\.map/)
    expect(src).toMatch(/\{!templatesUnavailable && visibleTemplates\.length === 0 && templates\.length > 0 && \(/)
    expect(src).toMatch(/\.catch\(\(\) => setTemplatesUnavailable\(true\)\)/)
    expect(src).not.toMatch(/\.catch\(\(\) => setTemplates\(\[\]\)\)/)
  })

  it('mutes leftover leftover-selected catalog id after a failed templates GET', () => {
    expect(src).toMatch(/apiFetch\('\/api\/template-engine\/templates'\)/)
    expect(src).toMatch(/value=\{templatesUnavailable \? '' : selectedId\}/)
    expect(src).toMatch(/\.catch\(\(\) => setTemplatesUnavailable\(true\)\)/)
    expect(src).not.toMatch(/setSelectedId\(''\)/)
    expect(src).not.toMatch(/value=\{error \? '' : selectedId\}/)
  })

  it('mutes leftover leftover-yaml after a failed template-body GET without using shared run error', () => {
    expect(src).toMatch(/const \[yamlUnavailable, setYamlUnavailable\] = useState\(false\)/)
    expect(src).toMatch(/setYamlUnavailable\(false\)/)
    expect(src).toMatch(/setYamlUnavailable\(true\)/)
    expect(src).toMatch(/data-testid="template-engine-yaml-unavailable"/)
    expect(src).toMatch(/!!String\(yaml \|\| ''\)\.trim\(\) && !yamlUnavailable/)
    expect(src).toMatch(/\.catch\(\(e\) => \{\n        setYamlUnavailable\(true\)\n        setError\(e\?\.message \|\| t\(`\$\{NS\}\.load_failed`\)\)/)
    expect(src).toMatch(/setError\(e\?\.message \|\| t\(`\$\{NS\}\.run_failed`\)\)/)
    expect(src).not.toMatch(/setYaml\(''\)/)
    expect(src).not.toMatch(/yamlUnavailable \|\| error/)
  })
})
