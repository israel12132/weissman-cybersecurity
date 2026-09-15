import { describe, it, expect } from 'vitest'
import { readFileSync } from 'node:fs'
import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'

const src = readFileSync(
  join(dirname(fileURLToPath(import.meta.url)), 'SatelliteDroneMap.jsx'),
  'utf8',
)

describe('SatelliteDroneMap live-only truth', () => {
  it('does not paint a quiet-empty vuln trail when GET /api/clients/:id/findings fails', () => {
    expect(src).toMatch(/data-testid="satellite-drone-map-findings-unavailable"/)
    expect(src).toMatch(/findings_unavailable/)
    expect(src).toMatch(/setFindingsUnavailable\(true\)/)
    expect(src).not.toMatch(/\.catch\(\(\) => \{\}\)/)
  })

  it('mutes leftover vuln markers after a failed findings GET', () => {
    expect(src).toMatch(/\{mapZoomComplete && !findingsUnavailable && vulnMarkers\.length > 0 && \(/)
    expect(src).toMatch(/: mapZoomComplete && !findingsUnavailable\n        \? t\(`\$\{NS\}\.markersActive`\)/)
    expect(src).toMatch(/\.catch\(\(\) => setFindingsUnavailable\(true\)\)/)
    expect(src).not.toMatch(/\.catch\(\(\) => setVulnMarkers\(\[\]\)/)
    expect(src).not.toMatch(/\.catch\(\(\) => \{\s*setVulnMarkers\(\[\]\)/)
  })
})
