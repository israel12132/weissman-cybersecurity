import { afterEach, describe, expect, it, vi } from 'vitest'
import { downloadClientPdf, downloadClientXlsx } from './downloadClientReport.js'

function mockFetch(contentType, urlSink) {
  return vi.fn(async (url) => {
    urlSink.push(url)
    return {
      headers: {
        get: (h) => {
          if (h === 'Content-Type') return contentType
          if (h === 'Content-Disposition') return 'attachment; filename="Weissman_Board.xlsx"'
          return null
        },
      },
      blob: async () => new Blob(['PK']),
    }
  })
}

describe('downloadClientReport', () => {
  const origCreate = document.createElement
  const origCreateObjectURL = URL.createObjectURL
  const origRevoke = URL.revokeObjectURL

  afterEach(() => {
    document.createElement = origCreate
    URL.createObjectURL = origCreateObjectURL
    URL.revokeObjectURL = origRevoke
  })

  it('rejects unexpected content-type for PDF', async () => {
    const apiFetch = mockFetch('application/json', [])
    await expect(downloadClientPdf(apiFetch, 7)).rejects.toThrow(/unexpected content-type/)
  })

  it('downloads real xlsx from /export/xlsx with JWT fetch', async () => {
    const urls = []
    const clicked = []
    document.createElement = (tag) => {
      const el = origCreate.call(document, tag)
      if (tag === 'a') el.click = () => clicked.push(el.download)
      return el
    }
    URL.createObjectURL = () => 'blob:test'
    URL.revokeObjectURL = () => {}
    const apiFetch = mockFetch(
      'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
      urls,
    )
    const result = await downloadClientXlsx(apiFetch, 42)
    expect(urls).toEqual(['/api/clients/42/export/xlsx'])
    expect(clicked[0]).toBe('Weissman_Board.xlsx')
    expect(result.size).toBeGreaterThan(0)
  })
})
