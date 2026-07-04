import { describe, it, expect } from 'vitest'
import { buildDefaultEngineParams, prefillParamsForEngine } from './engineClientPrefill.js'
describe('engineClientPrefill defaults', () => {
  it('default params', () => expect(buildDefaultEngineParams('osint')).toBeTruthy())
  it('prefill', () => {
    const p = prefillParamsForEngine('osint', {}, {})
    expect(typeof p).toBe('object')
  })
})