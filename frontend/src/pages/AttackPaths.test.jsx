import { describe, it, expect } from 'vitest'
import { needsCrownJewelSeed } from './AttackPaths.jsx'

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
