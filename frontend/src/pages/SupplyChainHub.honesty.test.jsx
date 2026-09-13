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
})
