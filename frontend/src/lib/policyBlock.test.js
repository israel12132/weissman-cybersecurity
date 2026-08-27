import { describe, it, expect } from 'vitest'
import { isPolicyBlockFinding, isRoeDeniedJob, policyBlockReason } from './policyBlock.js'

describe('policyBlock', () => {
  it('recognizes a first-class RoE finding', () => {
    expect(isPolicyBlockFinding({
      type: 'policy_block',
      category: 'roe_denied',
      policy_block: true,
      error_code: 'roe_denied',
      healthy: false,
      title: 'RoE denied — scada_ics blocked',
    })).toBe(true)
    expect(isPolicyBlockFinding({ type: 'modbus_attack', severity: 'info' })).toBe(false)
    expect(isPolicyBlockFinding(null)).toBe(false)
  })

  it('job status blocked is RoE denied even with empty findings array on the wrapper', () => {
    const job = {
      status: 'blocked',
      result: {
        status: 'blocked',
        error_code: 'roe_denied',
        policy_block: true,
        reason: 'RoE DENIED (industrial_ot_disabled): OT probing not authorized',
        findings: [{ type: 'policy_block', category: 'roe_denied', policy_block: true }],
      },
    }
    expect(isRoeDeniedJob(job)).toBe(true)
    expect(policyBlockReason(job, [])).toContain('industrial_ot_disabled')
  })

  it('completed + empty findings is NOT a policy block (true clean scan)', () => {
    expect(isRoeDeniedJob({ status: 'completed', result: { status: 'ok', findings: [] } })).toBe(false)
    expect(isRoeDeniedJob({ status: 'completed', result: { findings: [] } })).toBe(false)
  })

  it('recognizes list-API overlay fields without nested result', () => {
    const job = {
      status: 'blocked',
      policy_block: true,
      error_code: 'roe_denied',
      reason: 'RoE DENIED (industrial_ot_disabled): OT probing not authorized',
    }
    expect(isRoeDeniedJob(job)).toBe(true)
    expect(policyBlockReason(job, [])).toContain('industrial_ot_disabled')
  })

  it('overlays blocked from result even if queue status is still completed', () => {
    expect(isRoeDeniedJob({
      status: 'completed',
      result: { status: 'blocked', error_code: 'roe_denied', policy_block: true },
    })).toBe(true)
  })
})
