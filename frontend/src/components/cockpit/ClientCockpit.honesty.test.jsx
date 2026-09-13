import { describe, it, expect } from 'vitest'
import { readFileSync } from 'node:fs'
import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'

const src = readFileSync(
  join(dirname(fileURLToPath(import.meta.url)), 'ClientCockpit.jsx'),
  'utf8',
)

describe('ClientCockpit live-only truth', () => {
  it('does not paint uptime from an unconfirmed health payload', () => {
    expect(src).toMatch(/running_async_jobs == null/)
    expect(src).toMatch(/data-testid=\{healthLive \? 'cockpit-health-live' : 'cockpit-health-unavailable'\}/)
    expect(src).toMatch(/health_unavailable/)
    expect(src).toMatch(/postgres_ok === false/)
  })

  it('does not launch poe-scan after run-all store-down', () => {
    const run = src.slice(
      src.indexOf('const runFullScan'),
      src.indexOf('if (!selectedClientId)'),
    )
    expect(run).not.toMatch(/poe-scan still runs even if it fails/)
    expect(run).not.toMatch(/catch \(_\)/)
    expect(run).toMatch(/\/api\/scan\/run-all/)
    expect(run).toMatch(/\/api\/poe-scan\/run/)
    expect(run).toMatch(/engage_failed/)
  })
})
