import { describe, it, expect } from 'vitest'
import { jobIsRoeBlocked, extractRoeDetails, displayJobStatus } from './roeBlocked.js'

describe('roeBlocked helpers', () => {
  it('does not treat a green empty scan as blocked', () => {
    const job = { status: 'completed', findings_count: 0, result: { status: 'ok', findings: [] } }
    expect(jobIsRoeBlocked(job)).toBe(false)
    expect(displayJobStatus(job)).toBe('completed')
  })

  it('detects structured roe_blocked on the job and nested result', () => {
    const listed = {
      status: 'completed',
      roe_blocked: true,
      roe: { control: 'industrial_ot_enabled', never_auto_enabled: true, client_id: 42 },
    }
    expect(jobIsRoeBlocked(listed)).toBe(true)
    expect(displayJobStatus(listed)).toBe('roe_blocked')
    expect(extractRoeDetails(listed).control).toBe('industrial_ot_enabled')

    const nested = {
      status: 'completed',
      result: {
        status: 'roe_blocked',
        roe_blocked: true,
        findings: [],
        roe: { control: 'industrial_ot_enabled', who_must_enable: 'tenant_admin' },
      },
    }
    expect(jobIsRoeBlocked(nested)).toBe(true)
    expect(extractRoeDetails(nested).who_must_enable).toBe('tenant_admin')
  })

  it('does not invent findings from a RoE block', () => {
    const job = {
      status: 'completed',
      roe_blocked: true,
      result: { status: 'roe_blocked', findings: [], roe_blocked: true },
    }
    expect(job.result.findings).toEqual([])
  })

  it('maps a completed job with nested result to roe_blocked, not completed', () => {
    const job = {
      status: 'completed',
      result: {
        status: 'roe_blocked',
        roe_blocked: true,
        findings: [],
        roe: {
          control: 'industrial_ot_enabled',
          client_id: 42,
          blocked_at: '2026-08-27T15:00:00Z',
          never_auto_enabled: true,
        },
      },
    }
    expect(displayJobStatus(job)).toBe('roe_blocked')
    expect(extractRoeDetails(job).client_id).toBe(42)
    expect(extractRoeDetails(job).blocked_at).toBe('2026-08-27T15:00:00Z')
    expect(extractRoeDetails(job).never_auto_enabled).toBe(true)
  })
})
