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
    expect(src).toMatch(/const handleExportCsv = useCallback\(\(\) => \{\n    if \(error\) return/)
    expect(src).toMatch(/exportDisabled=\{\!\!error \|\| !filteredFindings\.length\}/)
    expect(src).toMatch(/\{!error && \(\n      <p className="text-xs text-\[var\(--text-muted\)\] font-mono mb-6">/)
  })
})
