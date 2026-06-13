import { describe, it, expect } from 'vitest'
import { sanitizeFindingPlainText } from './sanitizeFinding'

describe('sanitizeFindingPlainText', () => {
  it('returns empty string for null/undefined', () => {
    expect(sanitizeFindingPlainText(null)).toBe('')
    expect(sanitizeFindingPlainText(undefined)).toBe('')
  })

  it('coerces non-strings to string', () => {
    expect(sanitizeFindingPlainText(42)).toBe('42')
    expect(sanitizeFindingPlainText(true)).toBe('true')
  })

  it('strips NUL bytes', () => {
    expect(sanitizeFindingPlainText('a\u0000b\u0000c')).toBe('abc')
  })

  it('removes HTML-like tags (defense-in-depth on top of React escaping)', () => {
    expect(sanitizeFindingPlainText('<script>alert(1)</script>hi')).toBe('alert(1)hi')
    expect(sanitizeFindingPlainText('<img src=x onerror=y>')).toBe('')
    expect(sanitizeFindingPlainText('text</div>more')).toBe('textmore')
  })

  it('preserves genuine math/comparison text that is not a tag', () => {
    // "< 3" has whitespace after '<', so it is not a tag and must survive.
    expect(sanitizeFindingPlainText('5 < 3 and 9 > 2')).toBe('5 < 3 and 9 > 2')
  })

  it('truncates oversized input with a marker', () => {
    const out = sanitizeFindingPlainText('x'.repeat(50), 10)
    expect(out.startsWith('x'.repeat(10))).toBe(true)
    expect(out).toContain('[truncated]')
  })

  it('leaves normal short text untouched', () => {
    expect(sanitizeFindingPlainText('CVE-2024-1234 reflected XSS')).toBe(
      'CVE-2024-1234 reflected XSS',
    )
  })
})
