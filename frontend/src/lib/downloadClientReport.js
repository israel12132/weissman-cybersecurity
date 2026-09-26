/**
 * Authenticated blob download for board PDF / real XLSX (never a naked <a href>
 * that drops the JWT).
 */
export async function downloadAuthenticatedReport(
  apiFetch,
  url,
  { expectType, fallbackName } = {},
) {
  const res = await apiFetch(url, { raw: true })
  const contentType = (res.headers.get('Content-Type') || '').toLowerCase()
  if (expectType && !contentType.includes(expectType.toLowerCase())) {
    const err = new Error(`unexpected content-type: ${contentType || 'unknown'}`)
    err.contentType = contentType
    throw err
  }
  const blob = await res.blob()
  const disposition = res.headers.get('Content-Disposition') || ''
  const match = disposition.match(/filename="?([^";\n]+)"?/)
  let filename = match ? match[1].trim() : fallbackName || 'Weissman_report'
  const objectUrl = URL.createObjectURL(blob)
  const a = document.createElement('a')
  a.href = objectUrl
  a.download = filename
  document.body.appendChild(a)
  a.click()
  document.body.removeChild(a)
  URL.revokeObjectURL(objectUrl)
  return { filename, contentType, size: blob.size }
}

export function downloadClientPdf(apiFetch, clientId) {
  return downloadAuthenticatedReport(apiFetch, `/api/clients/${clientId}/report/pdf`, {
    expectType: 'application/pdf',
    fallbackName: 'Weissman_Report.pdf',
  })
}

export function downloadClientXlsx(apiFetch, clientId) {
  return downloadAuthenticatedReport(apiFetch, `/api/clients/${clientId}/export/xlsx`, {
    expectType: 'spreadsheetml.sheet',
    fallbackName: 'Weissman_Board.xlsx',
  })
}

/**
 * Open the self-contained HTML deliverable report (rendered server-side by report_studio) in a new
 * tab so the analyst can read it and print it to PDF (Ctrl/Cmd+P → Save as PDF). Authenticated: the
 * JWT is sent via apiFetch and the HTML is opened from a blob URL, never a naked <a href> that would
 * drop the token. `lang` is 'he' or 'en'.
 */
export async function openClientReportView(apiFetch, clientId, lang = 'en', kind = 'technical') {
  const code = lang === 'he' ? 'he' : 'en'
  const rk = kind === 'executive' || kind === 'board' ? 'executive' : 'technical'
  const res = await apiFetch(`/api/clients/${clientId}/report/view?lang=${code}&kind=${rk}`, {
    raw: true,
  })
  const contentType = (res.headers.get('Content-Type') || '').toLowerCase()
  if (!contentType.includes('text/html')) {
    throw new Error(`unexpected content-type: ${contentType || 'unknown'}`)
  }
  const blob = await res.blob()
  const objectUrl = URL.createObjectURL(blob)
  const win = window.open(objectUrl, '_blank', 'noopener,noreferrer')
  if (!win) {
    URL.revokeObjectURL(objectUrl)
    throw new Error('popup_blocked')
  }
  // Revoke after the tab has had time to load the document.
  setTimeout(() => URL.revokeObjectURL(objectUrl), 60_000)
  return { contentType, size: blob.size }
}
