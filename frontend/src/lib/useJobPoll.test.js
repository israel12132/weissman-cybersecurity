import { describe, it, expect } from 'vitest'
import { normalizeJobStatus, uiJobStatus, extractFindingsFromJob } from './useJobPoll.js'
describe('useJobPoll helpers', () => {
  it('normalizeJobStatus', () => expect(normalizeJobStatus('COMPLETED')).toBe('completed'))
  it('uiJobStatus', () => expect(typeof uiJobStatus('running')).toBe('string'))
  it('extractFindingsFromJob', () => {
    const f = extractFindingsFromJob({ result: { findings: [{ id: 1 }] } })
    expect(f.length).toBe(1)
  })
})