import { describe, it, expect } from 'vitest'
import { AGENT_REQUIRED_ENGINE_IDS, ENGINES_REGISTRY } from './enginesRegistry.js'

describe('requiresAgent catalog', () => {
  it('has unique agent-required IDs', () => {
    expect(new Set(AGENT_REQUIRED_ENGINE_IDS).size).toBe(AGENT_REQUIRED_ENGINE_IDS.length)
  })

  it('flags exactly the AGENT_REQUIRED_ENGINE_IDS set', () => {
    const flagged = ENGINES_REGISTRY.filter((e) => e.requiresAgent)
      .map((e) => e.id)
      .sort()
    expect(flagged).toEqual([...AGENT_REQUIRED_ENGINE_IDS].sort())
  })

  it('does not mark chronos as agent-only (server hybrid)', () => {
    expect(ENGINES_REGISTRY.find((e) => e.id === 'chronos')?.requiresAgent).toBe(false)
  })
})
