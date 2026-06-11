/**
 * API origin.
 *
 * Precedence:
 *   1. `import.meta.env.VITE_API_BASE_URL` — set at build time (e.g. https://api.weissman.io).
 *   2. `window.__WEISSMAN_API_BASE__` — set at runtime by index.html for self-hosted deploys.
 *   3. Empty string when running on the Vite dev server (port 5173 / 4173) so requests go through
 *      the dev proxy in vite.config.js.
 *   4. `window.location.origin` for production / same-origin deploys.
 *
 * No port is hardcoded. Returning an empty string defers to relative URLs.
 */
export function getApiBase() {
  if (typeof import.meta !== 'undefined' && import.meta.env) {
    const env = import.meta.env.VITE_API_BASE_URL
    if (env && String(env).trim()) return String(env).trim().replace(/\/+$/, '')
  }
  if (typeof window === 'undefined') return ''
  const runtime = window.__WEISSMAN_API_BASE__
  if (runtime && String(runtime).trim()) return String(runtime).trim().replace(/\/+$/, '')
  const port = window.location?.port
  if (port === '5173' || port === '4173') return '' // Vite dev/preview → use proxy
  return window.location?.origin || ''
}

export function apiUrl(path) {
  const base = getApiBase()
  const p = path.startsWith('/') ? path : `/${path}`
  return `${base}${p}`
}

const ACCESS_TOKEN_KEY = 'weissman_access_token'

let rateLimitToastCallback = null

/** Register a callback for 429 responses (used by RateLimitToast in AppShell). */
export function setRateLimitToastCallback(callback) {
  rateLimitToastCallback = callback
}

function parseRetryAfter(retryAfterHeader) {
  if (!retryAfterHeader) return 60
  const seconds = parseInt(retryAfterHeader, 10)
  if (!Number.isNaN(seconds)) return seconds
  try {
    const date = new Date(retryAfterHeader)
    const diff = Math.floor((date - new Date()) / 1000)
    return diff > 0 ? diff : 60
  } catch {
    return 60
  }
}

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
 * Attempt to refresh the access token using the refresh token cookie.
 * Returns true if refresh succeeded, false otherwise.
 */
async function tryRefreshToken() {
  try {
    const r = await fetch(apiUrl('/api/auth/refresh'), {
      method: 'POST',
      credentials: 'include',
      headers: { 'Content-Type': 'application/json' },
    })
    if (!r.ok) return false
    const data = await r.json().catch(() => ({}))
    if (data.ok && data.access_token) {
      setStoredAccessToken(data.access_token)
      return true
    }
    return false
  } catch {
    return false
  }
}

/**
 * Same-origin fetch with credentials + optional Bearer from sessionStorage.
 * On 401, attempts automatic token refresh and retries once.
 * @param {string} pathOrUrl path starting with `/` or absolute URL
 */
export async function apiFetch(pathOrUrl, init = {}) {
  if (pathOrUrl == null || pathOrUrl === '') {
    return Promise.reject(new TypeError('apiFetch: path or URL is required'))
  }
  const pathStr = String(pathOrUrl)
  const url = pathStr.startsWith('http') ? pathStr : apiUrl(pathStr)
  
  const doFetch = () => {
    const headers = new Headers(init.headers || {})
    const ah = authHeaders()
    if (ah.Authorization) headers.set('Authorization', ah.Authorization)
    const method = String(init.method || 'GET').toUpperCase()
    const withInit =
      method === 'GET' && init.cache === undefined ? { ...init, cache: 'no-store' } : init
    return fetch(url, { credentials: 'include', ...withInit, headers })
  }
  
  const response = await doFetch()

  if (response.status === 429 && rateLimitToastCallback) {
    const retryAfter = parseRetryAfter(response.headers.get('Retry-After'))
    let message = 'Rate limit exceeded. Please wait before trying again.'
    try {
      const errorData = await response.clone().json()
      message = errorData.detail || errorData.message || message
    } catch {
      // ignore JSON parse errors
    }
    rateLimitToastCallback({ retryAfter, message })
  }

  // If 401 Unauthorized, attempt token refresh and retry
  if (response.status === 401 && !pathStr.includes('/api/auth/refresh') && !pathStr.includes('/api/login')) {
    const refreshed = await tryRefreshToken()
    if (refreshed) {
      // Retry the original request with the new token
      return doFetch()
    }
  }
  
  return response
}

/** Prefer HttpOnly cookie auth for EventSource (`withCredentials: true`). */
export function apiEventSourceUrl(pathWithQuery) {
  const p = pathWithQuery.startsWith('/') ? pathWithQuery : `/${pathWithQuery}`
  return apiUrl(p)
}

/** Short-lived SSE ticket when cookies cannot be sent (cross-origin / legacy Bearer fallback). */
export async function fetchSseTicket() {
  try {
    const r = await apiFetch('/api/auth/sse-ticket')
    if (!r.ok) return null
    const data = await r.json().catch(() => ({}))
    const ticket = data.ticket
    return ticket && String(ticket).trim() ? String(ticket).trim() : null
  } catch {
    return null
  }
}

/** Append scoped SSE ticket query param (fallback only — prefer cookie-only URLs). */
export function apiEventSourceUrlWithTicket(pathWithQuery, ticket) {
  const base = apiEventSourceUrl(pathWithQuery)
  if (!ticket) return base
  const sep = base.includes('?') ? '&' : '?'
  return `${base}${sep}sse_ticket=${encodeURIComponent(ticket)}`
}

/**
 * Resolve EventSource URL: cookie-only by default; fetch sse_ticket when Bearer fallback is needed.
 */
export async function resolveEventSourceUrl(pathWithQuery) {
  const base = apiEventSourceUrl(pathWithQuery)
  if (getStoredAccessToken()) {
    const ticket = await fetchSseTicket()
    if (ticket) return apiEventSourceUrlWithTicket(pathWithQuery, ticket)
  }
  return base
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
