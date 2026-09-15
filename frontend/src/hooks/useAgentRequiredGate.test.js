import { describe, it, expect } from 'vitest'
import { evaluateAgentRequiredGate } from './useAgentRequiredGate'

describe('evaluateAgentRequiredGate', () => {
  const agent = {
    engineId: 'ebpf_sensor',
    isAgentRequired: true,
    fleetLoading: false,
    fleetUnavailable: false,
    hasOnlineAgent: false,
  }

  it('blocks only when the fleet endpoint reported zero online agents', () => {
    expect(evaluateAgentRequiredGate(agent)).toEqual({
      waiting: false,
      unknown: false,
      blocked: true,
    })
  })

  it('does not treat an unreachable fleet API as an empty roster', () => {
    expect(evaluateAgentRequiredGate({ ...agent, fleetUnavailable: true })).toEqual({
      waiting: false,
      unknown: true,
      blocked: false,
    })
  })

  it('keeps the surface open when a stale snapshot still has an online agent', () => {
    expect(
      evaluateAgentRequiredGate({
        ...agent,
        fleetUnavailable: true,
        hasOnlineAgent: true,
      }),
    ).toEqual({ waiting: false, unknown: false, blocked: false })
  })

  it('does not block remote engines while fleet status is down', () => {
    expect(
      evaluateAgentRequiredGate({
        engineId: 'osint',
        isAgentRequired: false,
        fleetLoading: false,
        fleetUnavailable: true,
        hasOnlineAgent: false,
      }),
    ).toEqual({ waiting: false, unknown: false, blocked: false })
  })

  it('waits while the fleet request is in flight', () => {
    expect(evaluateAgentRequiredGate({ ...agent, fleetLoading: true })).toEqual({
      waiting: true,
      unknown: false,
      blocked: false,
    })
  })

  it('does not gate when no engine id is bound', () => {
    expect(evaluateAgentRequiredGate({ ...agent, engineId: null })).toEqual({
      waiting: false,
      unknown: false,
      blocked: false,
    })
  })
})
