import { apiFetch } from '../utils/apiFetch'

/**
 * Authenticated binary download (PDF / XLSX / CSV). Uses apiFetch so Bearer +
 * cookie auth both work — a raw <a href> would miss the Authorization header.
 */
export async function downloadApiFile(path, fallbackName) {
  const r = await apiFetch(path, { raw: true })
  const disposition = r.headers.get('content-disposition') || ''
  const match = disposition.match(/filename="?([^";\n]+)"?/)
  const filename = match?.[1] ?? fallbackName
  const blob = await r.blob()
  const url = URL.createObjectURL(blob)
  const a = document.createElement('a')
  a.href = url
  a.download = filename
  document.body.appendChild(a)
  a.click()
  a.remove()
  URL.revokeObjectURL(url)
  return filename
}
