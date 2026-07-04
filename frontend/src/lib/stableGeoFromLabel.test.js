import { describe, it, expect } from 'vitest'
import { stableGeoFromLabel } from './stableGeoFromLabel.js'
describe('stableGeoFromLabel', () => {
  it('deterministic', () => {
    expect(stableGeoFromLabel('foo')).toEqual(stableGeoFromLabel('foo'))
  })
  it('israel shortcut', () => {
    const [lat] = stableGeoFromLabel('israel')
    expect(lat).toBeCloseTo(32.0853, 1)
  })
})