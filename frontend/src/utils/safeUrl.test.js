import { describe, it, expect } from 'vitest'
import { isHttpUrl, safeHttpHref } from './safeUrl.js'

describe('safeUrl — href scheme allowlist (anti clickjacking/XSS)', () => {
  it('accepts http and https absolute URLs', () => {
    expect(isHttpUrl('https://example.com/a?b=1')).toBe(true)
    expect(isHttpUrl('http://10.0.0.1:8080/x')).toBe(true)
  })

  it('rejects javascript:, data: and other dangerous schemes', () => {
    expect(isHttpUrl('javascript:alert(1)')).toBe(false)
    expect(isHttpUrl('JavaScript:alert(1)')).toBe(false)
    expect(isHttpUrl('data:text/html,<script>alert(1)</script>')).toBe(false)
    expect(isHttpUrl('vbscript:msgbox(1)')).toBe(false)
    expect(isHttpUrl('file:///etc/passwd')).toBe(false)
  })

  it('rejects empty / non-string / unparseable values', () => {
    expect(isHttpUrl('')).toBe(false)
    expect(isHttpUrl('   ')).toBe(false)
    expect(isHttpUrl(null)).toBe(false)
    expect(isHttpUrl(undefined)).toBe(false)
    expect(isHttpUrl(42)).toBe(false)
  })

  it('safeHttpHref returns the URL when safe and undefined otherwise', () => {
    expect(safeHttpHref('https://ok.test')).toBe('https://ok.test')
    expect(safeHttpHref('javascript:alert(1)')).toBeUndefined()
  })
})
