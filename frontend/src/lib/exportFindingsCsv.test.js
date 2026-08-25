import { describe, it, expect } from 'vitest'
import { exportStandardFindingsCsv, escapeCsvCell, downloadCsv } from './exportFindingsCsv'

describe('exportFindingsCsv', () => {
  it('escapes quotes in CSV cells', () => {
    expect(escapeCsvCell('say "hello"')).toBe('"say ""hello"""')
  })

  it('neutralizes spreadsheet formula injection (leading = + - @)', () => {
    expect(escapeCsvCell('=1+1')).toBe(`"'=1+1"`)
    expect(escapeCsvCell('+SUM(A1:A2)')).toBe(`"'+SUM(A1:A2)"`)
    expect(escapeCsvCell('-2+3')).toBe(`"'-2+3"`)
    expect(escapeCsvCell('@cmd')).toBe(`"'@cmd"`)
    expect(escapeCsvCell('=HYPERLINK("http://evil","x")')).toBe(`"'=HYPERLINK(""http://evil"",""x"")"`)
    // ordinary text is untouched
    expect(escapeCsvCell('SQL injection in /login')).toBe('"SQL injection in /login"')
    expect(escapeCsvCell(null)).toBe('""')
  })

  it('prefixes UTF-8 BOM so Excel opens Hebrew columns', () => {
    const orig = document.createElement
    let href = ''
    document.createElement = (tag) => {
      const el = orig.call(document, tag)
      if (tag === 'a') el.click = () => { href = el.download }
      return el
    }
    const blobs = []
    const OrigBlob = globalThis.Blob
    globalThis.Blob = class extends OrigBlob {
      constructor(parts, opts) {
        blobs.push(parts)
        super(parts, opts)
      }
    }
    URL.createObjectURL = () => 'blob:test'
    URL.revokeObjectURL = () => {}
    downloadCsv([['שלום']], ['col'], 'he-export')
    document.createElement = orig
    globalThis.Blob = OrigBlob
    const joined = blobs[0].join('')
    expect(joined.charCodeAt(0)).toBe(0xfeff)
    expect(href).toMatch(/^he-export-/)
  })

  it('exports header and rows', () => {
    const clicked = []
    const orig = document.createElement
    document.createElement = (tag) => {
      const el = orig.call(document, tag)
      if (tag === 'a') {
        el.click = () => clicked.push(el.download)
      }
      return el
    }
    URL.createObjectURL = () => 'blob:test'
    URL.revokeObjectURL = () => {}

    exportStandardFindingsCsv(
      [{ severity: 'high', title: 'Test', type: 'jwt', description: 'd', remediation: 'r' }],
      'test-export',
    )

    document.createElement = orig
    expect(clicked.length).toBe(1)
    expect(clicked[0]).toMatch(/^test-export-\d{4}-\d{2}-\d{2}\.csv$/)
  })
})
