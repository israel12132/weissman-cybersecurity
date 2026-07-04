import { describe, it, expect } from 'vitest'
import { openSseStream } from './sseStream.js'
describe('openSseStream', () => {
  it('returns handle', () => {
    const h = openSseStream('/api/events')
    expect(h).toHaveProperty('close')
    h.close()
  })
})