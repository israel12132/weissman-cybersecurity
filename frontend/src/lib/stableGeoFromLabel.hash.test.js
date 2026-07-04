import { describe, it, expect } from 'vitest'
import { stableGeoFromLabel } from './stableGeoFromLabel.js'
describe('stableGeoFromLabel hash', () => {
  it('different labels', () => {
    expect(stableGeoFromLabel('a')).not.toEqual(stableGeoFromLabel('b'))
  })
})