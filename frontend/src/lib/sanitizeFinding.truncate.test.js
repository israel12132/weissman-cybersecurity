import { describe, it, expect } from 'vitest'
import { sanitizeFindingPlainText } from './sanitizeFinding.js'
describe('sanitizeFinding truncate', () => {
  it('max len', () => expect(sanitizeFindingPlainText('abc', 2)).toContain('[truncated]'))
})