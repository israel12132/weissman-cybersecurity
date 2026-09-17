import { describe, it, expect } from 'vitest'
import { readFileSync } from 'node:fs'
import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'

const src = readFileSync(
  join(dirname(fileURLToPath(import.meta.url)), 'SystemCore.jsx'),
  'utf8',
)

describe('SystemCore live-only truth', () => {
  it('does not paint auto-sync-on or payload zeros before status is confirmed', () => {
    expect(src).toMatch(/const \[payloadSyncActive, setPayloadSyncActive\] = useState\(null\)/)
    expect(src).toMatch(/data-testid=\{payloadSyncActive == null \? 'payload-sync-unavailable' : 'payload-sync-status'\}/)
    expect(src).toMatch(/auto_sync_unavailable/)
    expect(src).not.toMatch(/live_payloads_count \?\? 0/)
    expect(src).not.toMatch(/active_ephemeral_count \?\? 0/)
  })

  it('does not paint no_payloads when GET /api/payload-sync/payloads is unconfirmed', () => {
    expect(src).toMatch(/const \[recentPayloads, setRecentPayloads\] = useState\(null\)/)
    expect(src).toMatch(/function payloadsFrom\(/)
    expect(src).toMatch(/data-testid="system-core-payloads-unavailable"/)
    expect(src).toMatch(/payloads_unavailable/)
    expect(src).not.toMatch(/\.catch\(\(\) => \(\{ payloads: \[\] \}\)\)/)
    expect(src).not.toMatch(/Array\.isArray\(data\?\.payloads\) \? data\.payloads : \[\]/)
  })
})
