import { describe, it, expect } from 'vitest'
import { GROUP_PARAMS } from './engineParamDefsGroups.js'
describe('engineParamDefsGroups', () => {
  it('groups object', () => expect(typeof GROUP_PARAMS).toBe('object'))
})