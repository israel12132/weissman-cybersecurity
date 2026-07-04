import { describe, it, expect } from 'vitest'
import { clientPrimaryTargetUrl, resolveClient, engineRunsWithoutTarget } from './clientTarget.js'
describe('clientTarget', () => {
  it('builds https URL', () => {
    expect(clientPrimaryTargetUrl({ domains: '["example.com"]' })).toBe('https://example.com')
  })
  it('resolveClient', () => {
    expect(resolveClient('1', [{ id: 1 }])).toMatchObject({ id: 1 })
  })
  it('targetless engines', () => {
    expect(engineRunsWithoutTarget('zero_day_radar')).toBe(true)
  })
})