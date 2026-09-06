/**
 * Authenticated download of a client's live assessment (PDF or Excel).
 * Uses the JWT/cookie `apiFetch` path — never a naked <a href> that drops auth.
 */

import { apiFetch } from '../utils/apiFetch'

const XLSX_MIME = 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet'

export function clientReportPath(clientId, format) {
  const id = encodeURIComponent(String(clientId))
  return format === 'xlsx'
    ? `/api/clients/${id}/export/xlsx`
    : `/api/clients/${id}/report/pdf`
}

export function reportLang(language) {
  return String(language || 'en').toLowerCase().startsWith('he') ? 'he' : 'en'
}

function filenameFromDisposition(disposition, format) {
  const header = disposition || ''
  const star = header.match(/filename\*=UTF-8''([^;]+)/i)
  if (star?.[1]) {
    try {
      return decodeURIComponent(star[1].trim().replace(/["']/g, ''))
    } catch {
      // fall through
    }
  }
  const quoted = header.match(/filename="([^"]+)"/i)
  if (quoted?.[1]) return quoted[1].trim()
  const bare = header.match(/filename=([^;]+)/i)
  if (bare?.[1]) return bare[1].trim().replace(/["']/g, '')
  return format === 'xlsx' ? 'Weissman_Assessment.xlsx' : 'Weissman_Assessment.pdf'
}

function triggerBlobDownload(blob, filename) {
  const url = URL.createObjectURL(blob)
  const a = document.createElement('a')
  a.href = url
  a.download = filename
  a.rel = 'noopener'
  document.body.appendChild(a)
  a.click()
  a.remove()
  URL.revokeObjectURL(url)
}

/**
 * @param {string|number} clientId
 * @param {'pdf'|'xlsx'} format
 * @param {string} [language]
 */
export async function downloadClientReport(clientId, format, language) {
  if (clientId == null || clientId === '') {
    throw new Error('client required')
  }
  const lang = reportLang(language)
  const path = `${clientReportPath(clientId, format)}?lang=${encodeURIComponent(lang)}`
  const res = await apiFetch(path, { raw: true })
  const contentType = res.headers.get('Content-Type') || ''
  if (format === 'pdf' && !contentType.includes('application/pdf')) {
    throw new Error(`unexpected type: ${contentType || 'unknown'}`)
  }
  if (
    format === 'xlsx'
    && !contentType.includes('spreadsheetml')
    && !contentType.includes('octet-stream')
    && !contentType.includes(XLSX_MIME)
  ) {
    throw new Error(`unexpected type: ${contentType || 'unknown'}`)
  }
  const blob = await res.blob()
  const filename = filenameFromDisposition(res.headers.get('Content-Disposition'), format)
  triggerBlobDownload(blob, filename)
  return filename
}
