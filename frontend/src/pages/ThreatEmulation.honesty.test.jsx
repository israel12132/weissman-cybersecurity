import { describe, it, expect } from 'vitest'
import { readFileSync } from 'node:fs'
import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'

const src = readFileSync(
  join(dirname(fileURLToPath(import.meta.url)), 'ThreatEmulation.jsx'),
  'utf8',
)

describe('ThreatEmulation live-only truth', () => {
  it('does not paint leftover leftover-history as a clean APT trail when GET /api/engines/history fails', () => {
    expect(src).toMatch(/data-testid="threat-emulation-history-unavailable"/)
    expect(src).toMatch(/history_unavailable/)
    expect(src).toMatch(/setHistoryUnavailable\(true\)/)
    expect(src).toMatch(/apiFetch\('\/api\/engines\/history\/threat_emulation\?limit=20'\)/)
  })

  it('does not dump leftover leftover-findings CSV after a failed history GET', () => {
    expect(src).toMatch(/const handleExportCsv = useCallback\(\(\) => \{\n {4}if \(historyUnavailable\) return/)
    expect(src).toMatch(/exportDisabled=\{historyUnavailable \|\| !filteredFindings\.length\}/)
  })

  it('mutes leftover leftover-GET Export CSV after a failed history GET', () => {
    expect(src).toMatch(/apiFetch\('\/api\/engines\/history\/threat_emulation\?limit=20'\)/)
    expect(src).toMatch(/onExport=\{historyUnavailable \? undefined : handleExportCsv\}/)
    expect(src).toMatch(/onRefresh=\{handleRefresh\}/)
    expect(src).toMatch(/data-testid="threat-emulation-history-unavailable"/)
    expect(src).toMatch(/showToast\('error', d\.detail \|\| d\.error \|\| t\('pages\.threatEmulation\.emulation_failed'\)\)/)
    expect(src).toMatch(/showToast\('error', e\?\.message \?\? t\('pages\.threatEmulation\.network_error'\)\)/)
    expect(src).toMatch(/setHistoryUnavailable\(true\)/)
    expect(src).not.toMatch(/onExport=\{exportCsv\}/)
  })
})
