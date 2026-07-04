import { describe, it, expect } from 'vitest'
import { clientPrimaryTargetUrl } from './clientTarget.js'
describe('clientTarget domains', () => {
  it('array domains', () => {
    expect(clientPrimaryTargetUrl({ domains: ['x.test'] })).toBe('https://x.test')
  })
  it('empty', () => expect(clientPrimaryTargetUrl({})).toBe(''))
})