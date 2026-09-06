import { describe, it, expect, vi, beforeEach } from 'vitest'
import { downloadClientReport, clientReportPath, reportLang } from './downloadClientReport.js'

const { apiFetch } = vi.hoisted(() => ({ apiFetch: vi.fn() }))
vi.mock('../utils/apiFetch', () => ({ apiFetch }))

function mockResponse({ type, disposition, body = 'file' }) {
  return {
    headers: {
      get: (name) => {
        if (name === 'Content-Type') return type
        if (name === 'Content-Disposition') return disposition
        return null
      },
    },
    blob: async () => new Blob([body], { type }),
  }
}

beforeEach(() => {
  apiFetch.mockReset()
  document.body.innerHTML = ''
  URL.createObjectURL = vi.fn(() => 'blob:mock')
  URL.revokeObjectURL = vi.fn()
})

describe('downloadClientReport', () => {
  it('requests the live PDF with lang and triggers a download', async () => {
    apiFetch.mockResolvedValue(mockResponse({
      type: 'application/pdf',
      disposition: 'attachment; filename="Weissman_Assessment_Acme.pdf"',
    }))
    const name = await downloadClientReport(42, 'pdf', 'he-IL')
    expect(apiFetch).toHaveBeenCalledWith('/api/clients/42/report/pdf?lang=he', { raw: true })
    expect(name).toBe('Weissman_Assessment_Acme.pdf')
  })

  it('requests the live Excel workbook', async () => {
    apiFetch.mockResolvedValue(mockResponse({
      type: 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
      disposition: 'attachment; filename="Weissman_Assessment_Acme.xlsx"',
    }))
    const name = await downloadClientReport(7, 'xlsx', 'en')
    expect(apiFetch).toHaveBeenCalledWith('/api/clients/7/export/xlsx?lang=en', { raw: true })
    expect(name).toBe('Weissman_Assessment_Acme.xlsx')
  })

  it('rejects a JSON body pretending to be a PDF', async () => {
    apiFetch.mockResolvedValue(mockResponse({ type: 'application/json', disposition: '' }))
    await expect(downloadClientReport(1, 'pdf', 'en')).rejects.toThrow(/unexpected type/)
  })

  it('maps paths and language', () => {
    expect(clientReportPath(9, 'xlsx')).toBe('/api/clients/9/export/xlsx')
    expect(reportLang('he')).toBe('he')
    expect(reportLang('en-US')).toBe('en')
  })
})
