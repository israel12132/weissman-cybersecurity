import { describe, it, expect } from 'vitest'
import { readinessGaps } from './attackReadiness'

describe('readinessGaps', () => {
  it('drops empty strings', () => {
    expect(readinessGaps(null)).toEqual([])
    expect(readinessGaps({ gaps: ['a', '', '  ', 'b'] })).toEqual(['a', 'b'])
  })
})
