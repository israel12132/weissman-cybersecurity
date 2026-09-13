import { describe, it, expect } from 'vitest'
import { readFileSync } from 'node:fs'
import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'

const src = readFileSync(
  join(dirname(fileURLToPath(import.meta.url)), 'CeoIntegratedCommandDeck.jsx'),
  'utf8',
)

describe('CeoIntegratedCommandDeck live-only truth', () => {
  it('does not paint safe-mode OFF or zero jobs when telemetry fields are null', () => {
    expect(src).not.toMatch(/const globalSafe = !!tel\?\.global_safe_mode/)
    expect(src).toMatch(/typeof liveTel\?\.global_safe_mode === 'boolean'/)
    expect(src).not.toMatch(/tenant_jobs_running \?\? 0/)
    expect(src).toMatch(/safeModeUnknown/)
  })

  it('does not paint scanning idle when both god and telemetry flags are unconfirmed', () => {
    expect(src).toMatch(/typeof scanFromGod === 'boolean'/)
    expect(src).toMatch(/typeof scanFromTel === 'boolean'/)
    expect(src).toMatch(/scanningKnown/)
    expect(src).toMatch(/scanningKnown \? !!scanningActive : null/)
  })

  it('does not paint leftover leftover-telemetry KPIs after a failed ceo telemetry poll', () => {
    expect(src).toMatch(/const liveTel = telErr \? null : tel/)
    expect(src).toMatch(/const liveGod = godErr \? null : god/)
    expect(src).toMatch(/liveTel \? formatUptime\(liveTel\.uptime_secs, t\) : '—'/)
    expect(src).toMatch(/disabled=\{safeSaving \|\| !liveTel \|\| !safeModeKnown\}/)
    expect(src).toMatch(/disabled=\{killSaving \|\| !liveTel\}/)
    expect(src).toMatch(/setTelErr\(e\.message \|\| t\('components\.ceo\.integratedCommandDeck\.telemetryFailed'\)\)/)
    expect(src).not.toMatch(/setTel\(null\)/)
  })
})
