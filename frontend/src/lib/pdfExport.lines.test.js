import { describe, it, expect } from 'vitest'
import { buildSimpleTextPdf } from './pdfExport.js'
describe('pdfExport lines', () => {
  it('multi line', () => {
    const b = buildSimpleTextPdf(['a', 'b', 'c'])
    expect(b.byteLength).toBeGreaterThan(50)
  })
})