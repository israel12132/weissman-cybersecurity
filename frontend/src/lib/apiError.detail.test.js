import { describe, it, expect } from 'vitest'
import { formatApiErrorFromBody } from './apiError.js'
describe('apiError detail variants', () => {
  it('message field', () => expect(formatApiErrorFromBody({ message: 'm' }, 400)).toBe('m'))
  it('array detail', () => {
    expect(formatApiErrorFromBody({ detail: [{ msg: 'a' }] }, 422)).toContain('a')
  })
})