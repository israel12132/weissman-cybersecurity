import { describe, it, expect } from 'vitest'
import { readFileSync } from 'node:fs'
import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'

const src = readFileSync(
  join(dirname(fileURLToPath(import.meta.url)), 'IacSecurityCenter.jsx'),
  'utf8',
)

describe('IacSecurityCenter live-only truth', () => {
  it('does not paint a green risk-0 gauge when GET /api/engines/history fails', () => {
    expect(src).toMatch(/data-testid="iac-security-history-unavailable"/)
    expect(src).toMatch(/history_unavailable/)
    expect(src).toMatch(/setHistoryUnavailable\(true\)/)
    expect(src).toMatch(/const hasScore = score != null/)
    expect(src).not.toMatch(/Math\.min\(100, Math\.max\(0, score \?\? 0\)\)/)
    expect(src).not.toMatch(/no fabricated history/)
  })

  it('does not paint unmeasured attack-paths when a live summary has zero chains', () => {
    expect(src).toMatch(/historyUnavailable \? '—' : \(liveSummary \? attackChains\.length : '—'\)/)
    expect(src).not.toMatch(/attackChains\.length \|\| '—'/)
  })

  it('does not paint five numeric 0 severity bars when summary is unconfirmed', () => {
    expect(src).toMatch(/!historyUnavailable && liveSummary\?\.by_severity/)
    expect(src).not.toMatch(/<SeverityBars bySeverity=\{summary\?\.by_severity\} \/>/)
    expect(src).toMatch(/const liveSummary = historyUnavailable \? null : summary/)
  })

  it('does not paint leftover leftover-compliance theatre from raw summary after a failed history GET', () => {
    expect(src).toMatch(/const livePolicyFindings = historyUnavailable \? \[\] : policyFindings/)
    expect(src).toMatch(/WaiversPanel waivers=\{liveSummary\?\.policy_waivers_applied\}/)
    expect(src).toMatch(/historyUnavailable \? '—' : `\$\{shownFindings\.length\}\/\$\{policyFindings\.length\}`/)
    expect(src).toMatch(/historyUnavailable\s*\n\s*\? t\('iacSecurity\.history_unavailable'\)/)
    expect(src).not.toMatch(/WaiversPanel waivers=\{summary\?\.policy_waivers_applied\}/)
  })

  it('does not dump leftover leftover-summary JSON after a failed history GET', () => {
    expect(src).toMatch(/const exportBundle = useCallback\(\(\) => \{\n    if \(historyUnavailable\) return/)
    expect(src).toMatch(/const exportAuditPacket = useCallback\(\(\) => \{\n    if \(historyUnavailable\) return/)
    expect(src).toMatch(/const exportGateEvidence = useCallback\(\(\) => \{\n    if \(historyUnavailable\) return/)
    expect(src).toMatch(/const exportFixBundle = useCallback\(\(\) => \{\n    if \(historyUnavailable\) return/)
    expect(src).toMatch(/const exportShellScript = useCallback\(\(\) => \{\n    if \(historyUnavailable\) return/)
  })

  it('does not dump leftover leftover-policy CSV after a failed history GET', () => {
    expect(src).toMatch(/const exportFindingsCsv = useCallback\(\(\) => \{\n    if \(historyUnavailable\) return/)
    expect(src).toMatch(/exportDisabled=\{historyUnavailable \|\| !shownFindings\.length\}/)
  })

  it('mutes leftover leftover-GET Export CSV after a failed history GET', () => {
    expect(src).toMatch(/apiFetch\('\/api\/engines\/history\/iac_misconfig\?limit=1'\)/)
    expect(src).toMatch(/onExport=\{historyUnavailable \? undefined : exportFindingsCsv\}/)
    expect(src).toMatch(/onRefresh=\{loadLastScan\}/)
    expect(src).toMatch(/data-testid="iac-security-history-unavailable"/)
    expect(src).toMatch(/if \(!ok\) \{ appendLine\(`\[ERROR\] \$\{data\.detail \|\| 'scan failed'\}`\); setRunning\(false\); return \}/)
    expect(src).toMatch(/setHistoryUnavailable\(true\)/)
    expect(src).not.toMatch(/onExport=\{exportFindingsCsv\}/)
  })

  it('does not paint leftover leftover-last-scan after a failed history GET', () => {
    expect(src).toMatch(/\{lastScanAt && !historyUnavailable && \(/)
  })

  it('does not paint leftover leftover-GET last-run telemetry after a failed history GET', () => {
    expect(src).toMatch(/const liveTelemetryLines = historyUnavailable/)
    expect(src).toMatch(/lines\.filter\(\(l\) => !String\(l\)\.includes\('\[IaC\] Loaded last run'\)\)/)
    expect(src).toMatch(/liveTelemetryLines\.length \? liveTelemetryLines\.join\('\\n'\)/)
    expect(src).not.toMatch(/appendLine\(`\[IaC\] Loaded last run/)
    expect(src).toMatch(/setHistoryUnavailable\(true\)/)
  })
})
