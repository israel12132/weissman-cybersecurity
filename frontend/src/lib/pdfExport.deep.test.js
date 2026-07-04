import { describe, it, expect } from 'vitest'
import { downloadBytes, buildSimpleTextPdf } from './pdfExport.js'

describe('pdfExport downloadBytes', () => {
  it('creates blob link', () => {
    const clicked = []
    const orig = document.createElement
    document.createElement = (tag) => {
      const el = orig.call(document, tag)
      if (tag === 'a') el.click = () => clicked.push(1)
      return el
    }
    URL.createObjectURL = () => 'blob:test'
    URL.revokeObjectURL = () => {}
    downloadBytes(buildSimpleTextPdf(['line']), 'evidence.pdf', 'application/pdf')
    document.createElement = orig
    expect(clicked.length).toBe(1)
  })
})
