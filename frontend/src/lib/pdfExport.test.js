import { describe, it, expect } from 'vitest'
import { buildSimpleTextPdf } from './pdfExport.js'
describe('pdfExport', () => {
  it('PDF magic', () => {
    const b = buildSimpleTextPdf(['Evidence'])
    expect(new TextDecoder().decode(b.slice(0, 8))).toBe('%PDF-1.4')
  })
})