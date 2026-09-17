import { describe, it, expect } from 'vitest'
import { readFileSync } from 'node:fs'
import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'

const src = readFileSync(
  join(dirname(fileURLToPath(import.meta.url)), 'DigitalTwinSimulator.jsx'),
  'utf8',
)

describe('DigitalTwinSimulator live-only truth', () => {
  it('does not paint an empty tenant picker when GET /api/clients fails', () => {
    expect(src).toMatch(/data-testid="digital-twin-clients-unavailable"/)
    expect(src).toMatch(/clients_unavailable/)
    expect(src).toMatch(/setClientsUnavailable\(true\)/)
    expect(src).not.toMatch(/\.catch\(\(\) => setClients\(\[\]\)\)/)
  })

  it('does not paint not_run_hint when GET /api/engines/history fails', () => {
    expect(src).toMatch(/data-testid="digital-twin-history-unavailable"/)
    expect(src).toMatch(/history_unavailable/)
    expect(src).toMatch(/unavailable=\{historyUnavailable\}/)
    expect(src).toMatch(/!historyUnavailable/)
  })

  it('does not paint leftover leftover-scorecard after a failed history GET', () => {
    expect(src).toMatch(/!historyUnavailable && summary && <Scorecard/)
    expect(src).toMatch(/!historyUnavailable && summary/)
    expect(src).not.toMatch(/summary\.score \?\? 0/)
    expect(src).not.toMatch(/Number\(value\) \|\| 0/)
  })

  it('does not paint leftover leftover-twin-profile paths after a failed history GET', () => {
    expect(src).toMatch(/!historyUnavailable && <TwinProfilePanel/)
  })

  it('does not dump leftover leftover-findings CSV after a failed history GET', () => {
    expect(src).toMatch(/const handleExportCsv = useCallback\(\(\) => \{\n {4}if \(historyUnavailable\) return/)
    expect(src).toMatch(/exportDisabled=\{historyUnavailable \|\| !filteredFindings\.length\}/)
  })

  it('mutes leftover leftover-GET Export CSV after a failed history GET', () => {
    expect(src).toMatch(/useWeissmanEnginePage\(ENGINE, detailFindings\)/)
    expect(src).toMatch(/onExport=\{historyUnavailable \? undefined : handleExportCsv\}/)
    expect(src).toMatch(/onRefresh=\{handleRefresh\}/)
    expect(src).toMatch(/data-testid="digital-twin-history-unavailable"/)
    expect(src).toMatch(/showToast\('error', d\.detail \|\| t\('pages\.digitalTwinSimulator\.simulation_failed'\)\)/)
    expect(src).toMatch(/showToast\('error', e\?\.message \?\? t\('common\.error'\)\)/)
    expect(src).not.toMatch(/setHistoryUnavailable/)
  })

})
