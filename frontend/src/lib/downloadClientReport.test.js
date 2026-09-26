import { afterEach, describe, expect, it, vi } from 'vitest'
import {
  downloadClientPdf,
  downloadClientXlsx,
  openClientReportView,
} from './downloadClientReport.js'

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
  const origOpen = window.open

  afterEach(() => {
    document.createElement = origCreate
    URL.createObjectURL = origCreateObjectURL
    URL.revokeObjectURL = origRevoke
    window.open = origOpen
    vi.useRealTimers()
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

  describe('openClientReportView (Report Studio HTML deliverable)', () => {
    it('opens the authenticated HTML report in a new tab from a blob URL and revokes it later', async () => {
      vi.useFakeTimers()
      const urls = []
      const opened = []
      const revoked = []
      URL.createObjectURL = () => 'blob:report'
      URL.revokeObjectURL = (u) => revoked.push(u)
      window.open = (url, target, features) => {
        opened.push({ url, target, features })
        return {}
      }
      const apiFetch = mockFetch('text/html; charset=utf-8', urls)
      const result = await openClientReportView(apiFetch, 42, 'he', 'technical')
      // JWT fetch through apiFetch (never a naked <a href> that would drop the token), raw Response.
      expect(urls).toEqual(['/api/clients/42/report/view?lang=he&kind=technical'])
      expect(apiFetch.mock.calls[0][1]).toEqual({ raw: true })
      expect(opened).toEqual([
        { url: 'blob:report', target: '_blank', features: 'noopener,noreferrer' },
      ])
      expect(result.contentType).toContain('text/html')
      expect(result.size).toBeGreaterThan(0)
      // The object URL stays valid long enough for the tab to load, then is released.
      expect(revoked).toEqual([])
      vi.advanceTimersByTime(60_000)
      expect(revoked).toEqual(['blob:report'])
    })

    it('normalises language and kind: unknown lang → en, board → executive', async () => {
      const urls = []
      URL.createObjectURL = () => 'blob:report'
      URL.revokeObjectURL = () => {}
      window.open = () => ({})
      const apiFetch = mockFetch('text/html', urls)
      await openClientReportView(apiFetch, 7, 'fr', 'board')
      await openClientReportView(apiFetch, 7)
      expect(urls).toEqual([
        '/api/clients/7/report/view?lang=en&kind=executive',
        '/api/clients/7/report/view?lang=en&kind=technical',
      ])
    })

    it('refuses a non-HTML response instead of opening a tab', async () => {
      const opened = []
      window.open = (u) => {
        opened.push(u)
        return {}
      }
      const apiFetch = mockFetch('application/json', [])
      await expect(openClientReportView(apiFetch, 7, 'en')).rejects.toThrow(
        /unexpected content-type/,
      )
      expect(opened).toEqual([])
    })

    it('reports a blocked popup and revokes the object URL immediately', async () => {
      const revoked = []
      URL.createObjectURL = () => 'blob:blocked'
      URL.revokeObjectURL = (u) => revoked.push(u)
      window.open = () => null
      const apiFetch = mockFetch('text/html', [])
      await expect(openClientReportView(apiFetch, 7, 'en')).rejects.toThrow('popup_blocked')
      expect(revoked).toEqual(['blob:blocked'])
    })
  })
})
