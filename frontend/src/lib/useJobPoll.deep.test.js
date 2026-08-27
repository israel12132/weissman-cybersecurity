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

  it('uiJobStatus maps RoE-blocked jobs distinctly from completed', () => {
    expect(uiJobStatus('completed')).toBe('completed')
    expect(uiJobStatus('completed', { status: 'completed', roe_blocked: true })).toBe('roe_blocked')
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
