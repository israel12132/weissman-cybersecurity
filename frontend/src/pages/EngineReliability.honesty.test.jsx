import { describe, it, expect } from 'vitest'
import { readFileSync } from 'node:fs'
import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'

const src = readFileSync(
  join(dirname(fileURLToPath(import.meta.url)), 'EngineReliability.jsx'),
  'utf8',
)

describe('EngineReliability live-only truth', () => {
  it('does not paint catalog or telemetry zeros when capabilities or telemetry are unconfirmed', () => {
    expect(src).toMatch(/data-testid="engine-reliability-unavailable"/)
    expect(src).toMatch(/unavailable_title/)
    expect(src).toMatch(/telemUnavailable \? '—'/)
    expect(src).toMatch(/recoveryRate == null \? '—'/)
    expect(src).toMatch(/pages\.engineReliability\.unconfirmed/)
    expect(src).toMatch(/telemUnavailable \? t\('pages\.engineReliability\.unconfirmed'\)/)
    expect(src).not.toMatch(/telem\.total_runs \?\? 0/)
    expect(src).not.toMatch(/telem\.engines_observed \?\? 0/)
  })

  it('does not dump leftover leftover-telemetry after a failed telemetry GET', () => {
    expect(src).toMatch(/health: telemUnavailable \? null : \(telemById\[c\.id\] \|\| null\)/)
    expect(src).toMatch(/!telemUnavailable && \(telem\?\.failed_runs \?\? 0\) > 0 && \(/)
    expect(src).toMatch(/telemUnavailable \|\| !telem \|\| typeof telem\.total_runs !== 'number'/)
    expect(src).toMatch(/const handleExportCsv = useCallback\(\(\) => \{\n    if \(telemError\) return/)
    expect(src).toMatch(/exportDisabled=\{\!\!telemError \|\| !filteredFindings\.length\}/)
  })
})
