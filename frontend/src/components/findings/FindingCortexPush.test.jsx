import { describe, it, expect } from 'vitest'
import { canPushFindingToCortex } from './FindingCortexPush.jsx'

describe('canPushFindingToCortex', () => {
  it('allows confirmed live verdicts', () => {
    expect(canPushFindingToCortex({ live_verdict: 'CONFIRMED' })).toBe(true)
    expect(canPushFindingToCortex({ live_verification: { verdict: 'LIKELY_VALID' } })).toBe(true)
  })

  it('blocks noise', () => {
    expect(canPushFindingToCortex({ live_verdict: 'NOISE' })).toBe(false)
    expect(canPushFindingToCortex({ live_verdict: 'FALSE_POSITIVE' })).toBe(false)
  })

  it('allows proof artifacts without a verdict', () => {
    expect(canPushFindingToCortex({ raw: { oast_callback: 'https://oast.example/x' } })).toBe(true)
  })

  it('rejects empty findings', () => {
    expect(canPushFindingToCortex({})).toBe(false)
    expect(canPushFindingToCortex(null)).toBe(false)
  })
})
