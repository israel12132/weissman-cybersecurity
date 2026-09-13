import { describe, it, expect } from 'vitest'
import { readFileSync } from 'node:fs'
import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'

const src = readFileSync(
  join(dirname(fileURLToPath(import.meta.url)), 'NexusSovereignSwarm.jsx'),
  'utf8',
)

describe('NexusSovereignSwarm live-only truth', () => {
  it('does not paint ready-to-scan when GET /api/engines/history fails', () => {
    expect(src).toMatch(/data-testid="nexus-sovereign-swarm-history-unavailable"/)
    expect(src).toMatch(/history_unavailable/)
    expect(src).toMatch(/unavailable=\{historyUnavailable\}/)
    expect(src).toMatch(/!historyUnavailable/)
  })

  it('does not paint a cyan-0 SIQ ring or fallback agentCount when swarm metrics are unconfirmed', () => {
    expect(src).toMatch(/const hasScore = score != null && Number\.isFinite\(Number\(score\)\)/)
    expect(src).not.toMatch(/const pct = Math\.min\(100, Math\.max\(0, score \?\? 0\)\)/)
    expect(src).toMatch(/const liveMetrics = historyUnavailable \? null : metrics/)
    expect(src).toMatch(/liveMetrics\?\.agents_deployed != null \? liveMetrics\.agents_deployed\.toLocaleString\(\) : '—'/)
    expect(src).not.toMatch(/metrics\?\.agents_deployed\?\.toLocaleString\(\) \?\? agentCount\.toLocaleString\(\)/)
    expect(src).not.toMatch(/threat_surface_score \?\? intel\?\.threat_surface_score \?\? 0/)
    expect(src).toMatch(/liveMetrics\?\.endpoint_agents_bridged != null \? liveMetrics\.endpoint_agents_bridged : '—'/)
    expect(src).not.toMatch(/metrics\?\.endpoint_agents_bridged \?\? fleetOnline/)
  })

  it('does not dump leftover leftover-intelligence JSON after a failed history GET', () => {
    expect(src).toMatch(/const handleExportReport = useCallback\(\(\) => \{\n    if \(historyUnavailable\) return/)
    expect(src).toMatch(/!historyUnavailable && \(metrics \|\| realFindings\.length > 0\)/)
  })
})
