import { describe, it, expect } from 'vitest'
import { filenameFromDisposition } from './authenticatedDownload.js'

describe('filenameFromDisposition', () => {
  it('reads a quoted Content-Disposition filename', () => {
    expect(filenameFromDisposition('attachment; filename="Weissman_Dominion_Acme.xlsx"', 'x.bin')).toBe(
      'Weissman_Dominion_Acme.xlsx',
    )
  })

  it('falls back when the header is missing', () => {
    expect(filenameFromDisposition('', 'board.xlsx')).toBe('board.xlsx')
    expect(filenameFromDisposition(null, 'report.pdf')).toBe('report.pdf')
  })
})
