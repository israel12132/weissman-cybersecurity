import { describe, it, expect } from 'vitest'
import { readFileSync } from 'node:fs'
import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'

const src = readFileSync(
  join(dirname(fileURLToPath(import.meta.url)), 'OtIcsSecurity.jsx'),
  'utf8',
)

describe('OtIcsSecurity live-only truth', () => {
  it('does not paint a confirmed-empty OT inventory when GET /api/ot-ics/devices fails', () => {
    expect(src).toMatch(/data-testid="ot-ics-devices-unavailable"/)
    expect(src).toMatch(/unavailable_title/)
    expect(src).toMatch(/setDevicesUnavailable\(true\)/)
    expect(src).toMatch(/Array\.isArray\(data\?\.devices\)/)
    expect(src).not.toMatch(/console\.error\('Failed to fetch OT devices:'/)
  })

  it('does not hide a failed fingerprint trail as an empty panel', () => {
    expect(src).toMatch(/data-testid="ot-ics-fingerprints-unavailable"/)
    expect(src).toMatch(/fingerprints_unavailable/)
    expect(src).toMatch(/setFingerprintsUnavailable\(true\)/)
    expect(src).not.toMatch(/setFingerprints\(\[\]\);\s*\}\s*catch/)
  })

  it('does not paint scan-findings-ready when GET /api/engines/history fails', () => {
    expect(src).toMatch(/data-testid="ot-ics-scan-history-unavailable"/)
    expect(src).toMatch(/scan_history_unavailable/)
    expect(src).toMatch(/setScanHistoryUnavailable\(true\)/)
    expect(src).toMatch(/classifyEngineHistory/)
    expect(src).toMatch(/showEmptyReady=\{!scanHistoryUnavailable\}/)
    expect(src).not.toMatch(/history unavailable — still refresh the device inventory below/)
  })
})
