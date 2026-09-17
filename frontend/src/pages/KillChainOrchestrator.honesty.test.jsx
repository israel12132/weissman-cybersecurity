import { describe, it, expect } from 'vitest'
import { readFileSync } from 'node:fs'
import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'

const src = readFileSync(
  join(dirname(fileURLToPath(import.meta.url)), 'KillChainOrchestrator.jsx'),
  'utf8',
)

describe('KillChainOrchestrator live-only truth', () => {
  it('does not paint zero chains as a quiet ATT&CK surface when load fails', () => {
    expect(src).toMatch(/data-testid="kill-chain-unavailable"/)
    expect(src).toMatch(/unavailable_title/)
    expect(src).toMatch(/error \? null : chains\.length === 0/)
  })

  it('does not dump leftover leftover-chain CSV after a failed findings GET', () => {
    expect(src).toMatch(/const handleExportCsv = useCallback\(\(\) => \{\n {4}if \(error\) return/)
    expect(src).toMatch(/exportDisabled=\{!!error \|\| !filteredFindings\.length\}/)
    expect(src).toMatch(/\{!error && \(\n {6}<p className="text-xs text-\[var\(--text-muted\)\] font-mono mb-6">/)
  })

  it('mutes leftover leftover-GET Export CSV after a failed kill-chain GET', () => {
    expect(src).toMatch(/apiFetch\('\/api\/soc\/kill-chains'\)/)
    expect(src).toMatch(/apiFetch\('\/api\/findings\?limit=2000'\)/)
    expect(src).toMatch(/const handleExportCsv = useCallback\(\(\) => \{\n {4}if \(error\) return/)
    expect(src).toMatch(/onExport=\{error \? undefined : handleExportCsv\}/)
    expect(src).toMatch(/exportDisabled=\{!!error \|\| !filteredFindings\.length\}/)
    expect(src).toMatch(/onRefresh=\{loadKillChainData\}/)
    expect(src).not.toMatch(/setFindings\(\[\]\)/)
  })
})
