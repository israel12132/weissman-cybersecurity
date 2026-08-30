import { describe, it, expect } from 'vitest'
import {
  normalizeJobStatus,
  uiJobStatus,
  extractFindingsFromJob,
  resolveJobFindings,
} from './useJobPoll.js'

describe('useJobPoll deep', () => {
  it('normalizeJobStatus variants', () => {
    expect(normalizeJobStatus('running')).toBe('running')
    expect(normalizeJobStatus('')).toBe('')
    expect(normalizeJobStatus(null)).toBe('')
  })

  it('uiJobStatus maps terminal states', () => {
    expect(uiJobStatus('completed')).toMatch(/complete|done|success/i)
    expect(uiJobStatus('failed')).toMatch(/fail|error/i)
    expect(uiJobStatus('blocked')).toBe('blocked')
  })

  it('extractFindingsFromJob nested arrays', () => {
    const rows = extractFindingsFromJob({
      result: { data: { findings: [{ id: 2 }] } },
      findings: [{ id: 3 }],
    })
    expect(rows.length).toBeGreaterThan(0)
  })

  it('resolveJobFindings prefers job payload', async () => {
    const rows = await resolveJobFindings(
      { result: { findings: [{ id: 9, title: 'x' }] }, status: 'completed' },
      'osint',
      1,
    )
    expect(rows.some((r) => r.id === 9)).toBe(true)
  })
})
