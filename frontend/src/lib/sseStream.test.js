import { describe, it, expect } from 'vitest'
import { SSE_CONNECTING, SSE_OPEN, SSE_CLOSED } from './sseStream.js'
describe('sseStream constants', () => {
  it('states', () => {
    expect(SSE_CONNECTING).toBe(0)
    expect(SSE_OPEN).toBe(1)
    expect(SSE_CLOSED).toBe(2)
  })
})