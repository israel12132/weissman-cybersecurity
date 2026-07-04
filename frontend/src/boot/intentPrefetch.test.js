import { describe, it, expect } from 'vitest'
import { predictChainFromRoute } from './intentPrefetch.js'
describe('intentPrefetch', () => {
  it('predicts chain without throw', () => {
    expect(() => predictChainFromRoute('/command-center/operations')).not.toThrow()
  })
})