import { describe, it, expect } from 'vitest'
import { readFileSync } from 'node:fs'
import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'

const src = readFileSync(
  join(dirname(fileURLToPath(import.meta.url)), 'RiskGraphVisualization.jsx'),
  'utf8',
)

describe('RiskGraphVisualization live-only truth', () => {
  it('does not paint zero assets when the risk graph or attack-paths fetch is unconfirmed', () => {
    expect(src).toMatch(/data-testid="risk-graph-unavailable"/)
    expect(src).toMatch(/unavailable_title/)
    expect(src).toMatch(/clientsUnavailable/)
    expect(src).toMatch(/setGraphUnavailable\(true\)/)
    expect(src).not.toMatch(/\.catch\(\(\) => null\)/)
  })

  it('does not dump leftover leftover-graph CSV/JSON after a failed graph GET', () => {
    expect(src).toMatch(/const handleExportCsv = useCallback\(\(\) => \{\n {4}if \(graphUnavailable\) return/)
    expect(src).toMatch(/exportDisabled=\{graphUnavailable \|\| !filteredFindings\.length\}/)
    expect(src).toMatch(/if \(graphUnavailable \|\| clientId == null\) return/)
    expect(src).toMatch(/disabled=\{graphUnavailable \|\| clientId == null \|\| !graphData\.nodes\.length\}/)
    expect(src).toMatch(/catch \(error\) \{\n {6}console\.error\('Failed to fetch graph data:', error\);\n {6}setGraphUnavailable\(true\);/)
    expect(src).not.toMatch(/catch \(error\) \{\s*console\.error\('Failed to fetch graph data:', error\);\s*setGraphData/)
  })

  it('mutes leftover leftover-GET Export JSON after a failed graph GET', () => {
    expect(src).toMatch(/withClientId\('\/api\/risk\/graph'/)
    expect(src).toMatch(/\{!graphUnavailable && \(\s*<Button variant="unstyled"\s*type="button"\s*onClick=\{exportGraphJson\}/)
    expect(src).toMatch(/if \(graphUnavailable \|\| clientId == null\) return/)
    expect(src).toMatch(/\$\{NS\}\.export_json/)
    expect(src).toMatch(/setGraphUnavailable\(true\)/)
  })

  it('mutes leftover leftover-GET Export CSV after a failed graph GET', () => {
    expect(src).toMatch(/withClientId\('\/api\/risk\/graph'/)
    expect(src).toMatch(/api\.get\(`\/api\/attack-paths\/\$\{cid\}`\)/)
    expect(src).toMatch(/const handleExportCsv = useCallback\(\(\) => \{\n {4}if \(graphUnavailable\) return/)
    expect(src).toMatch(/onExport=\{graphUnavailable \? undefined : handleExportCsv\}/)
    expect(src).toMatch(/exportDisabled=\{graphUnavailable \|\| !filteredFindings\.length\}/)
    expect(src).toMatch(/catch \(error\) \{\n {6}console\.error\('Failed to fetch graph data:', error\);\n {6}setGraphUnavailable\(true\);/)
    expect(src).not.toMatch(/catch \(error\) \{\s*console\.error\('Failed to fetch graph data:', error\);\s*setGraphData/)
  })
})
