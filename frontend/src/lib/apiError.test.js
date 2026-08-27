import { describe, it, expect } from 'vitest'
import { formatApiErrorFromBody, scanIntakeErrorMessage } from './apiError.js'
describe('apiError', () => {
  it('detail string', () => expect(formatApiErrorFromBody({ detail: 'x' }, 400)).toBe('x'))
  it('status fallback', () => expect(formatApiErrorFromBody(null, 502)).toContain('502'))
  it('maps no_default_scan_target', () => {
    const data = {
      ok: false,
      error_code: 'no_default_scan_target',
      detail: 'Add a domain',
    }
    expect(scanIntakeErrorMessage(data, 400, (k) => k)).toBe('errors.no_default_scan_target')
    expect(scanIntakeErrorMessage(data, 400)).toBe('Add a domain')
  })
  it('maps target_out_of_scope', () => {
    const data = { ok: false, error_code: 'target_out_of_scope', detail: 'outside' }
    expect(scanIntakeErrorMessage(data, 403, (k) => k)).toBe('errors.target_out_of_scope')
    expect(scanIntakeErrorMessage(data, 403)).toBe('outside')
  })
})