/**
 * Authenticated file download via apiFetch so short-lived access cookies can
 * refresh. Direct <a download> skips /api/auth refresh and 401s an otherwise
 * valid session.
 */
import { apiFetch } from '../utils/apiFetch.js'

export function filenameFromDisposition(disposition, fallback = 'download') {
  const match = String(disposition || '').match(/filename="?([^";\s]+)"?/)
  return match?.[1] || fallback
}

export async function downloadAuthenticated(path, { signal, fallbackName } = {}) {
  const r = await apiFetch(path, { raw: true, signal })
  const filename = filenameFromDisposition(
    r.headers.get('content-disposition'),
    fallbackName || 'download',
  )
  const blob = await r.blob()
  const url = URL.createObjectURL(blob)
  try {
    const a = document.createElement('a')
    a.href = url
    a.download = filename
    a.rel = 'noopener'
    a.click()
  } finally {
    URL.revokeObjectURL(url)
  }
  return filename
}
