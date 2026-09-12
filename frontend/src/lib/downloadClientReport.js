/**
 * Authenticated blob download for board PDF / real XLSX (never a naked <a href>
 * that drops the JWT).
 */
export async function downloadAuthenticatedReport(apiFetch, url, { expectType, fallbackName } = {}) {
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
  let filename = match ? match[1].trim() : (fallbackName || 'Weissman_report')
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
