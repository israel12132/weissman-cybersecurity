import { describe, it, expect } from 'vitest'
import { normalizeJobStatus, uiJobStatus } from './useJobPoll.js'
describe('job status mapping', () => {
  it('failed', () => expect(normalizeJobStatus('FAILED')).toBe('failed'))
  it('ui pending', () => expect(uiJobStatus('queued')).toBeTruthy())
  it('waiting_for_agent is in-progress, not success', () => {
    expect(normalizeJobStatus('waiting_for_agent')).toBe('waiting_for_agent')
    expect(uiJobStatus('waiting_for_agent')).toBe('running')
  })
})