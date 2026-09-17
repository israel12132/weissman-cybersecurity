import { describe, it, expect } from 'vitest'
import { readFileSync } from 'node:fs'
import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'

const src = readFileSync(
  join(dirname(fileURLToPath(import.meta.url)), 'SystemConfiguration.jsx'),
  'utf8',
)

describe('SystemConfiguration live-only truth', () => {
  it('does not dump leftover leftover-config CSV after a failed config GET', () => {
    expect(src).toMatch(/configUnavailable/)
    expect(src).toMatch(/const handleExportCsv = useCallback\(\(\) => \{\n    if \(configUnavailable\) return/)
    expect(src).toMatch(/exportDisabled=\{configUnavailable \|\| !filteredFindings\.length\}/)
  })

  it('mutes leftover leftover-MFA status after a failed MFA status GET', () => {
    expect(src).toMatch(/\{\!statusUnavailable && \(\n      <div className="text-\[11px\] font-mono text-\[var\(--text-tertiary\)\]">\n        \{t\(`\$\{NS\}\.mfa\.account_label`\)\}{' '\}\n        \{status\.mfa_enabled \? \(/)
    expect(src).toMatch(/\{\!statusUnavailable && status\.mfa_enabled && \(/)
    expect(src).toMatch(/setStatusUnavailable\(true\)/)
    expect(src).toMatch(/setErr\(e\?\.message \|\| t\(`\$\{NS\}\.mfa\.errors\.status_fetch_failed`\)\)/)
    expect(src).not.toMatch(/setStatusUnavailable\(true\)\n      setStatus\(null\)/)
  })

  it('mutes leftover leftover-GET Export CSV after a failed config GET', () => {
    expect(src).toMatch(/api\.get\('\/api\/system\/config'\)/)
    expect(src).toMatch(/const handleExportCsv = useCallback\(\(\) => \{\n    if \(configUnavailable\) return/)
    expect(src).toMatch(/onExport=\{configUnavailable \? undefined : handleExportCsv\}/)
    expect(src).toMatch(/exportDisabled=\{configUnavailable \|\| !filteredFindings\.length\}/)
    expect(src).toMatch(/onRefresh=\{fetchConfig\}/)
    expect(src).toMatch(/text: error\?\.message \|\| t\(`\$\{NS\}\.save_error`\)/)
    expect(src).not.toMatch(/save_error[\s\S]{0,80}setConfigUnavailable/)
    expect(src).not.toMatch(/Failed to fetch config:[\s\S]{0,80}setConfig\(/)
  })
})
