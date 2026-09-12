import { describe, it, expect } from 'vitest'
import {
  operatorState,
  operatorStateCounts,
  matchesOperatorFilter,
  remapLabel,
  diagnosticsHaystack,
  jobToCsvRow,
  mergeJobDiagnostics,
  OPERATOR_STATES,
} from './jobDiagnostics.js'

describe('jobDiagnostics', () => {
  it('prefers live operator_state over raw db status', () => {
    expect(operatorState({ status: 'running', operator_state: 'stuck' })).toBe('stuck')
    expect(operatorState({ status: 'pending' })).toBe('queued')
    expect(operatorState({ status: 'dead' })).toBe('error')
    expect(operatorState({ operator_state: 'blocked_by_agent' })).toBe('blocked_by_agent')
    expect(operatorState({ operator_state: 'roe_blocked' })).toBe('roe_blocked')
  })

  it('keeps empty/error/running/stuck/agent/roe distinct in counts', () => {
    const jobs = [
      { operator_state: 'queued' },
      { operator_state: 'running' },
      { operator_state: 'stuck' },
      { operator_state: 'blocked_by_agent' },
      { operator_state: 'roe_blocked' },
      { operator_state: 'error', status: 'failed' },
    ]
    const c = operatorStateCounts(jobs)
    expect(c.queued).toBe(1)
    expect(c.running).toBe(1)
    expect(c.stuck).toBe(1)
    expect(c.blocked_by_agent).toBe(1)
    expect(c.roe_blocked).toBe(1)
    expect(c.failed).toBe(1)
    expect(c.completed).toBe(0)
    expect(OPERATOR_STATES).toEqual(expect.arrayContaining([
      'stuck', 'blocked_by_agent', 'roe_blocked', 'error', 'running',
    ]))
  })

  it('filters by operator state, mapping failed to error', () => {
    const stuck = { operator_state: 'stuck' }
    const failed = { status: 'failed' }
    expect(matchesOperatorFilter(stuck, 'stuck')).toBe(true)
    expect(matchesOperatorFilter(stuck, 'running')).toBe(false)
    expect(matchesOperatorFilter(failed, 'failed')).toBe(true)
    expect(matchesOperatorFilter(stuck, 'all')).toBe(true)
  })

  it('surfaces remap requested vs canonical', () => {
    const j = {
      remap: {
        requested_engine: 'active_directory',
        canonical_engine: 'kerberos_attack_suite',
        was_remapped: true,
      },
    }
    expect(remapLabel(j)).toEqual({
      requested: 'active_directory',
      canonical: 'kerberos_attack_suite',
      wasRemapped: true,
    })
    expect(remapLabel({})).toBeNull()
  })

  it('includes stuck_reason and lease owner in search haystack', () => {
    const hay = diagnosticsHaystack({
      id: 'abc',
      stuck_reason: 'redis lease missing',
      lease_owner: 'box:9',
      remap: { requested_engine: 'active_directory', canonical_engine: 'kerberos_attack_suite', was_remapped: true },
    })
    expect(hay).toContain('redis lease missing')
    expect(hay).toContain('box:9')
    expect(hay).toContain('kerberos_attack_suite')
  })

  it('exports diagnostic columns on csv rows', () => {
    const row = jobToCsvRow({
      id: 'j1',
      kind: 'command_center_engine',
      status: 'running',
      operator_state: 'stuck',
      stuck_reason: 'worker heartbeat stale 400s',
      lease_owner: 'host:1',
      lease_present: false,
      heartbeat_stale_secs: 400,
    })
    expect(row).toContain('stuck')
    expect(row).toContain('worker heartbeat stale 400s')
    expect(row).toContain('host:1')
    expect(row).toContain(false)
  })

  it('merges live diagnostics onto the selected job without dropping identity', () => {
    const merged = mergeJobDiagnostics(
      { id: 'j1', status: 'running' },
      { operator_state: 'stuck', stuck_reason: 'redis lease missing', lease_owner: 'w1' },
    )
    expect(merged.id).toBe('j1')
    expect(merged.operator_state).toBe('stuck')
    expect(merged.lease_owner).toBe('w1')
  })
})
