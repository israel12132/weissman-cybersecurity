import { describe, it, expect } from 'vitest'
import { formatApiErrorFromBody } from './apiError.js'
describe('apiError', () => {
  it('detail string', () => expect(formatApiErrorFromBody({ detail: 'x' }, 400)).toBe('x'))
  it('status fallback', () => expect(formatApiErrorFromBody(null, 502)).toContain('502'))
})