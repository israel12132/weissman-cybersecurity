/**
 * Normalize backend JSON errors (Axum/serde, payment-required, validation arrays).
 */

export function formatApiErrorFromBody(data, status) {
  if (data == null || typeof data !== 'object') {
    return status ? `Request failed (HTTP ${status})` : 'Request failed'
  }
  const d = data.detail
  if (typeof d === 'string' && d.trim()) return d.trim()
  if (Array.isArray(d)) {
    const parts = d.map((x) => {
      if (x && typeof x === 'object' && typeof x.msg === 'string') return x.msg
      return String(x)
    })
    const joined = parts.filter(Boolean).join('; ')
    return joined || `HTTP ${status}`
  }
  if (typeof data.message === 'string' && data.message.trim()) return data.message.trim()
  if (typeof data.error === 'string' && data.error.trim()) return data.error.trim()
  if (data.ok === false && typeof data.detail === 'object') {
    try {
      return JSON.stringify(data.detail)
    } catch {
      /* ignore */
    }
  }
  return status ? `HTTP ${status}` : 'Request failed'
}

export async function formatApiErrorResponse(response) {
  const status = response.status
  let data = null
  const ct = response.headers.get('content-type') || ''
  try {
    const text = await response.text()
    if (ct.includes('application/json') && text) {
      try {
        data = JSON.parse(text)
      } catch {
        data = { detail: text }
      }
    } else if (text) {
      data = { detail: text }
    }
  } catch {
    data = null
  }
  return formatApiErrorFromBody(data, status)
}
