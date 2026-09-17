import { describe, it, expect } from 'vitest'
import { readFileSync } from 'node:fs'
import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'

const src = readFileSync(
  join(dirname(fileURLToPath(import.meta.url)), 'JwtAttackLab.jsx'),
  'utf8',
)

describe('JwtAttackLab live-only truth', () => {
  it('does not paint ready-to-assess when GET /api/engines/history fails', () => {
    expect(src).toMatch(/data-testid="jwt-attack-lab-history-unavailable"/)
    expect(src).toMatch(/history_unavailable/)
    expect(src).toMatch(/setHistoryUnavailable\(true\)/)
    expect(src).toMatch(/classifyEngineHistory/)
    expect(src).toMatch(/!historyUnavailable &&/)
    expect(src).not.toMatch(/honest empty — no seeded history/)
  })

  it('leftover leftover-KPIs do not hide the history-unavailable banner', () => {
    expect(src).toMatch(/scanResult && !scanResult\.pending && !historyUnavailable/)
    expect(src).toMatch(/!historyLoading && historyUnavailable &&/)
    expect(src).not.toMatch(/!scanResult && !historyLoading && historyUnavailable/)
  })

  it('does not dump leftover leftover-findings CSV after a failed history GET', () => {
    expect(src).toMatch(/const handleExportCsv = useCallback\(\(\) => \{\n {4}if \(historyUnavailable\) return/)
    expect(src).toMatch(/exportDisabled=\{historyUnavailable \|\| !filteredDisplayFindings\.length\}/)
  })

  it('mutes leftover leftover-GET Export CSV after a failed history GET', () => {
    expect(src).toMatch(/apiFetch\('\/api\/engines\/history\/jwt_attack\?limit=1'\)/)
    expect(src).toMatch(/onExport=\{historyUnavailable \? undefined : handleExportCsv\}/)
    expect(src).toMatch(/onRefresh=\{loadLastRun\}/)
    expect(src).toMatch(/data-testid="jwt-attack-lab-history-unavailable"/)
    expect(src).toMatch(/showToast\('error', d\.detail \|\| t\('pages\.jwtLab\.scan_failed'\)\)/)
    expect(src).not.toMatch(/scan_failed[\s\S]{0,80}setHistoryUnavailable/)
    expect(src).toMatch(/\} catch \{\n {6}setHistoryUnavailable\(true\)\n {4}\} finally \{/)
    expect(src).not.toMatch(/setHistoryUnavailable\(true\)\n {6}setScanResult/)
  })
})
