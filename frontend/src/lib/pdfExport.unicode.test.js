import { describe, it, expect } from 'vitest'
import {
  needsUnicodePdf,
  renderTextPdf,
  assembleImagePdf,
  buildSimpleTextPdf,
} from './pdfExport.js'

const magic = (bytes) => new TextDecoder().decode(bytes.slice(0, 8))
const text = (bytes) => new TextDecoder('utf-8', { fatal: false }).decode(bytes)

describe('needsUnicodePdf', () => {
  it('detects Hebrew and Arabic', () => {
    expect(needsUnicodePdf(['שלום עולם'])).toBe(true)
    expect(needsUnicodePdf(['مرحبا'])).toBe(true)
    expect(needsUnicodePdf(['report', 'ממצא'])).toBe(true)
  })
  it('is false for plain Latin/numeric content', () => {
    expect(needsUnicodePdf(['hello world', 'CVE-2024-1234', '42'])).toBe(false)
    expect(needsUnicodePdf([])).toBe(false)
  })
})

describe('renderTextPdf', () => {
  it('always returns a valid PDF (Latin path)', () => {
    const b = renderTextPdf(['Findings export', 'engine: asm'])
    expect(magic(b)).toBe('%PDF-1.4')
  })
  it('returns a valid PDF for Hebrew content (image path, or fallback under jsdom)', () => {
    const b = renderTextPdf(['דוח אבטחה', 'ממצא קריטי'])
    expect(magic(b)).toBe('%PDF-1.4')
    expect(b.byteLength).toBeGreaterThan(50)
  })
})

describe('assembleImagePdf', () => {
  // Minimal fake JPEG payload (SOI ... EOI); assembly is byte-exact regardless.
  const fakeJpeg = new Uint8Array([0xff, 0xd8, 0xff, 0xe0, 0x00, 0x10, 0xff, 0xd9])

  it('produces a single-page image PDF with a DCTDecode stream', () => {
    const b = assembleImagePdf([{ bytes: fakeJpeg, width: 100, height: 200 }])
    const s = text(b)
    expect(magic(b)).toBe('%PDF-1.4')
    expect(s).toContain('/Filter /DCTDecode')
    expect(s).toContain('/Subtype /Image')
    expect(s).toContain('/Count 1')
    expect(s).toContain('/Im0 Do')
    expect(s.trimEnd().endsWith('%%EOF')).toBe(true)
    expect(s).toContain(`/Length ${fakeJpeg.length}`)
  })

  it('supports multiple pages', () => {
    const b = assembleImagePdf([
      { bytes: fakeJpeg, width: 10, height: 10 },
      { bytes: fakeJpeg, width: 10, height: 10 },
    ])
    expect(text(b)).toContain('/Count 2')
  })

  it('falls back to a text PDF when given no pages', () => {
    expect(magic(assembleImagePdf([]))).toBe('%PDF-1.4')
  })
})

describe('buildSimpleTextPdf (unchanged Latin fallback)', () => {
  it('still emits the magic header', () => {
    expect(magic(buildSimpleTextPdf(['x']))).toBe('%PDF-1.4')
  })
})
