import { describe, it, expect } from 'vitest'
import { readFileSync } from 'node:fs'
import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'

const src = readFileSync(
  join(dirname(fileURLToPath(import.meta.url)), 'RemediationDetail.jsx'),
  'utf8',
)

const load = src.slice(src.indexOf('const loadBrief'), src.indexOf('// Auto-load the brief on open'))

describe('RemediationDetail live-only truth', () => {
  it('mutes leftover leftover-brief and leftover leftover-patch after a failed GET /brief', () => {
    expect(src).toMatch(/method: refresh \? 'POST' : 'GET'/)
    expect(src).toMatch(/setBriefUnavailable\(false\)/)
    expect(src).toMatch(/if \(!refresh\) setBriefUnavailable\(true\)/)
    expect(src).toMatch(/data-testid="remediation-brief-unavailable"/)
    expect(src).toMatch(/\{brief && !briefUnavailable && \(/)
    expect(src).toMatch(/\{patch && !briefUnavailable && \(/)
    expect(src).toMatch(/\{channelHowTo && !briefUnavailable && \(/)
    expect(src).toMatch(/pages\.remediationHub\.brief_unavailable/)
  })

  it('keeps leftover leftover-brief and leftover leftover-patch in state and does not catch-clear them', () => {
    expect(load).not.toMatch(/setBrief\(null\)/)
    expect(load).not.toMatch(/setPatch\(''\)/)
    expect(src).toMatch(/onClick=\{\(\) => loadBrief\(true\)\}/)
  })

  it('keeps briefUnavailable GET-only — generate POST briefError does not mute leftover leftover-brief', () => {
    expect(src).toMatch(/\{briefError && !briefUnavailable && \(/)
    expect(src).not.toMatch(/\{brief && !briefError && \(/)
    expect(src).not.toMatch(/\{patch && !briefError && \(/)
    expect(load).toMatch(/if \(!refresh\) setBriefUnavailable\(true\)/)
  })
})
