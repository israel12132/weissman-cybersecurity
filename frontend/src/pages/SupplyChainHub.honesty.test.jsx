import { describe, it, expect } from 'vitest'
import { readFileSync } from 'node:fs'
import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'

const src = readFileSync(
  join(dirname(fileURLToPath(import.meta.url)), 'SupplyChainHub.jsx'),
  'utf8',
)

describe('SupplyChainHub live-only truth', () => {
  it('does not paint an empty tenant picker when GET /api/clients fails', () => {
    expect(src).toMatch(/data-testid="supply-chain-hub-clients-unavailable"/)
    expect(src).toMatch(/clients_unavailable/)
    expect(src).toMatch(/setClientsUnavailable\(true\)/)
    expect(src).not.toMatch(/\.catch\(\(\) => \{\}\)/)
  })

  it('does not paint ready-to-scan when engine history GETs fail', () => {
    expect(src).toMatch(/data-testid="supply-chain-hub-history-unavailable"/)
    expect(src).toMatch(/history_unavailable/)
    expect(src).toMatch(/classifyEngineHistory/)
    expect(src).toMatch(/showEmptyReady=\{!historyUnavailable\}/)
    expect(src).not.toMatch(/Array\.isArray\(d\?\.runs\) \? d\.runs : \[\]/)
  })

  it('does not dump leftover leftover-findings CSV after a failed history GET', () => {
    expect(src).toMatch(/const handleExportCsv = useCallback\(\(\) => \{\n    if \(historyUnavailable\) return/)
    expect(src).toMatch(/exportDisabled=\{historyUnavailable \|\| !filteredFindings\.length\}/)
  })

  it('mutes leftover leftover-GET Export CSV after a failed history GET', () => {
    expect(src).toMatch(/apiFetch\(`\/api\/engines\/history\/\$\{id\}\?limit=1`\)/)
    expect(src).toMatch(/onExport=\{historyUnavailable \? undefined : handleExportCsv\}/)
    expect(src).toMatch(/onRefresh=\{handleRefresh\}/)
    expect(src).toMatch(/data-testid="supply-chain-hub-history-unavailable"/)
    expect(src).toMatch(/showToast\('error', d\.detail \|\| t\('pages\.supplyChainHub\.scan_failed'\)\)/)
    expect(src).toMatch(/showToast\('error', e\?\.message \?\? t\('common\.error'\)\)/)
    expect(src).toMatch(/setHistoryUnavailable\(anyUnavailable\)/)
    expect(src).not.toMatch(/setHistoryUnavailable\(true\)/)
  })

})
