/** API origin: Vite dev uses '' + proxy; production uses current origin. */
export function getApiBase() {
  if (typeof window === 'undefined') return ''
  if (window.location.port === '5173') return ''
  return window.location?.origin || ''
}

export function apiUrl(path) {
  const base = getApiBase()
  const p = path.startsWith('/') ? path : `/${path}`
  return `${base}${p}`
}

const ACCESS_TOKEN_KEY = 'weissman_access_token'

export function getStoredAccessToken() {
  if (typeof sessionStorage === 'undefined') return null
  const t = sessionStorage.getItem(ACCESS_TOKEN_KEY)
  return t && String(t).trim() ? String(t).trim() : null
}

export function setStoredAccessToken(token) {
  if (typeof sessionStorage === 'undefined') return
  if (token && String(token).trim()) sessionStorage.setItem(ACCESS_TOKEN_KEY, String(token).trim())
  else sessionStorage.removeItem(ACCESS_TOKEN_KEY)
}

export function clearStoredAccessToken() {
  if (typeof sessionStorage === 'undefined') return
  sessionStorage.removeItem(ACCESS_TOKEN_KEY)
}

/** Merge Bearer token for APIs when cookies are blocked (e.g. legacy Secure cookies on http://127.0.0.1). */
export function authHeaders() {
  const t = getStoredAccessToken()
  return t ? { Authorization: `Bearer ${t}` } : {}
}

/**
 * Same-origin fetch with credentials + optional Bearer from sessionStorage.
 * @param {string} pathOrUrl path starting with `/` or absolute URL
 */
export function apiFetch(pathOrUrl, init = {}) {
  if (pathOrUrl == null || pathOrUrl === '') {
    return Promise.reject(new TypeError('apiFetch: path or URL is required'))
  }
  const pathStr = String(pathOrUrl)
  const url = pathStr.startsWith('http') ? pathStr : apiUrl(pathStr)
  const headers = new Headers(init.headers || {})
  const ah = authHeaders()
  if (ah.Authorization) headers.set('Authorization', ah.Authorization)
  const method = String(init.method || 'GET').toUpperCase()
  const withInit =
    method === 'GET' && init.cache === undefined ? { ...init, cache: 'no-store' } : init
  return fetch(url, { credentials: 'include', ...withInit, headers })
}

/** EventSource cannot send Authorization; append access_token when stored (backend accepts query for SSE). */
export function apiEventSourceUrl(pathWithQuery) {
  const p = pathWithQuery.startsWith('/') ? pathWithQuery : `/${pathWithQuery}`
  const base = apiUrl(p)
  const t = getStoredAccessToken()
  if (!t) return base
  const sep = base.includes('?') ? '&' : '?'
  return `${base}${sep}access_token=${encodeURIComponent(t)}`
}

/**
 * Human-readable fetch error for CEO / dashboard calls (status + optional JSON body).
 */
export function formatHttpApiError(response, bodyDetail) {
  const st = response?.status
  const detail = typeof bodyDetail === 'string' && bodyDetail.trim() ? bodyDetail.trim() : ''
  const raw = detail || response?.statusText || ''
  if (st === 404) {
    return (
      'CEO API not on this server (HTTP 404). Deploy a current weissman-server build — routes ' +
      '/api/ceo/telemetry, /api/ceo/jobs/live, /api/ceo/god-mode/snapshot must exist. Then restart the service.'
    )
  }
  if (st === 401) {
    return (
      detail ||
      'Not authenticated (HTTP 401). Sign out and sign in again, or refresh the page so the JWT cookie and session token stay in sync.'
    )
  }
  if (st === 403) return detail || 'Forbidden — CEO role or superadmin required for this endpoint.'
  if (st === 400) return detail || 'Bad request (HTTP 400) — check the submitted data.'
  if (st === 502 || st === 503) return detail || `Upstream unavailable (HTTP ${st}).`
  if (st != null && st >= 500 && st < 600) {
    return detail || `Server error (HTTP ${st}). Retry or contact support if it persists.`
  }
  return raw || (st != null ? `HTTP ${st}` : 'Request failed')
}
