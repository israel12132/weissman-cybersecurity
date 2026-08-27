import { describe, it, expect } from 'vitest'
import { normalizeJobStatus, uiJobStatus, isTerminalJobStatus } from './useJobPoll.js'
describe('job status mapping', () => {
  it('failed', () => expect(normalizeJobStatus('FAILED')).toBe('failed'))
  it('blocked', () => expect(uiJobStatus('blocked')).toBe('blocked'))
  it('ui pending', () => expect(uiJobStatus('queued')).toBeTruthy())
  it('blocked is terminal', () => {
    expect(isTerminalJobStatus('blocked')).toBe(true)
    expect(isTerminalJobStatus('completed')).toBe(true)
    expect(isTerminalJobStatus('running')).toBe(false)
  })
})