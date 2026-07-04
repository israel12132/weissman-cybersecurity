import { describe, it, expect } from 'vitest'
import { normalizeJobStatus, uiJobStatus } from './useJobPoll.js'
describe('job status mapping', () => {
  it('failed', () => expect(normalizeJobStatus('FAILED')).toBe('failed'))
  it('ui pending', () => expect(uiJobStatus('queued')).toBeTruthy())
})