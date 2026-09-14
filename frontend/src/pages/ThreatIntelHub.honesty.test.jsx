import { describe, it, expect } from 'vitest'
import { readFileSync } from 'node:fs'
import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'

const src = readFileSync(
  join(dirname(fileURLToPath(import.meta.url)), 'ThreatIntelHub.jsx'),
  'utf8',
)

describe('ThreatIntelHub live-only truth', () => {
  it('mutes leftover leftover-GET Export CSV after a failed threat-intel feed GET', () => {
    expect(src).toMatch(/useApiResource\('\/api\/threat-intel\/feed'/)
    expect(src).toMatch(/onExport=\{feed\.unavailable \? undefined : feedWorkbench\.exportCsv\}/)
    expect(src).toMatch(/onRefresh=\{reloadAll\}/)
    expect(src).toMatch(/data-testid="threat-intel-feed-unavailable"/)
    expect(src).toMatch(/setUnavailable\(true\)/)
    expect(src).toMatch(/setUnavailable\(false\)/)
    expect(src).not.toMatch(/onExport=\{feedWorkbench\.exportCsv\}/)
    expect(src).not.toMatch(/onExport=\{kpis\./)
  })

  it('keeps feed Export CSV GET-only — exec-kpis error must not mute leftover leftover-feed CSV', () => {
    expect(src).toMatch(/useApiResource\('\/api\/dashboard\/exec-kpis'/)
    expect(src).toMatch(/const kpis = useApiResource\('\/api\/dashboard\/exec-kpis'/)
    expect(src).not.toMatch(/onExport=\{kpis\.unavailable/)
    expect(src).not.toMatch(/onExport=\{kpis\.error/)
    expect(src).not.toMatch(/method:\s*'POST'/)
  })
})
