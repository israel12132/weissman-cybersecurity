import { describe, it, expect } from 'vitest'
import { needsCrownJewelSeed, rankJewelCandidates, nodeFlagsPatch } from './attackPathSeeds'

describe('needsCrownJewelSeed', () => {
  it('is false without a snapshot', () => {
    expect(needsCrownJewelSeed(null)).toBe(false)
    expect(needsCrownJewelSeed(undefined)).toBe(false)
  })

  it('is true only when jewel_count is zero', () => {
    expect(needsCrownJewelSeed({ jewel_count: 0 })).toBe(true)
    expect(needsCrownJewelSeed({ jewel_count: '0' })).toBe(true)
    expect(needsCrownJewelSeed({ jewel_count: 3 })).toBe(false)
  })
})

describe('rankJewelCandidates', () => {
  it('drops honeypots and ranks jewels then risk', () => {
    const ranked = rankJewelCandidates([
      { id: 1, honey_node: true, risk_score: 99, label: 'honey' },
      { id: 2, crown_jewel: false, internet_exposed: true, risk_score: 10, label: 'entry' },
      { id: 3, crown_jewel: true, risk_score: 1, label: 'jewel' },
      { id: 4, crown_jewel: false, risk_score: 80, label: 'hot' },
    ])
    expect(ranked.map((n) => n.id)).toEqual([3, 2, 4])
  })
})

describe('nodeFlagsPatch', () => {
  it('PATCHes crown_jewel on the live flags route', () => {
    expect(nodeFlagsPatch(3, { crown_jewel: true })).toEqual({
      url: '/api/risk-graph/nodes/3/flags',
      opts: { method: 'PATCH', body: { crown_jewel: true } },
    })
  })
})
