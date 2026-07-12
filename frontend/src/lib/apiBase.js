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

/**
 * Access-token storage is tiered by XSS blast radius:
 *  1. `inMemoryAccessToken` (below) is the primary store — not reachable after
 *     the tab is closed and never written to disk.
 *  2. `sessionStorage` is a tab-scoped fallback (see getStoredAccessToken) so the
 *     token survives a same-tab reload before the HttpOnly refresh cookie +
 *     `tryRefreshToken()` rehydrate it. It IS readable by same-origin script, so
 *     it is deliberately *not* localStorage (no cross-tab/session persistence),
 *     and the strict CSP (`script-src 'self'`) is the primary defense against a
 *     script being injected to read it in the first place.
 * The token is never mirrored to localStorage; legacy copies are purged on access.
 */
let inMemoryAccessToken = null

/**
 * Remove any access token left behind in `localStorage` by older builds that
 * mirrored it there. The token must never live in `localStorage` — it persists
 * across tabs/sessions and is a prime XSS-exfiltration target.
 */
function purgeLegacyLocalStorageToken() {
  if (typeof localStorage === 'undefined') return
  try {
    localStorage.removeItem(ACCESS_TOKEN_KEY)
  } catch {
    /* storage access can throw in privacy modes — ignore */
  }
}

let rateLimitToastCallback = null

/** Register a callback for 429 responses (used by RateLimitToast in AppShell). */
export function setRateLimitToastCallback(callback) {
  rateLimitToastCallback = callback
}

/** Return the currently registered 429 toast callback (used by utils/apiFetch to share state). */
export function getRateLimitToastCallback() {
  return rateLimitToastCallback
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
  // Always clean up a token left in localStorage by an older build.
  purgeLegacyLocalStorageToken()
  if (inMemoryAccessToken) return inMemoryAccessToken
  // sessionStorage fallback: tab-scoped, cleared on tab close. Lets the token
  // survive same-tab reloads before the refresh cookie kicks in, without the
  // cross-session persistence (and XSS blast radius) of localStorage.
  if (typeof sessionStorage === 'undefined') return null
  const t = sessionStorage.getItem(ACCESS_TOKEN_KEY)
  if (t && String(t).trim()) {
    inMemoryAccessToken = String(t).trim()
    return inMemoryAccessToken
  }
  return null
}

export function setStoredAccessToken(token) {
  purgeLegacyLocalStorageToken()
  if (token && String(token).trim()) {
    const v = String(token).trim()
    inMemoryAccessToken = v
    if (typeof sessionStorage !== 'undefined') sessionStorage.setItem(ACCESS_TOKEN_KEY, v)
  } else {
    inMemoryAccessToken = null
    if (typeof sessionStorage !== 'undefined') sessionStorage.removeItem(ACCESS_TOKEN_KEY)
  }
}

export function clearStoredAccessToken() {
  inMemoryAccessToken = null
  purgeLegacyLocalStorageToken()
  if (typeof sessionStorage !== 'undefined') sessionStorage.removeItem(ACCESS_TOKEN_KEY)
}

/** True only for same-origin or the configured API-origin URLs — the only places
 *  the bearer token may be attached. */
export function isSameApiOrigin(url) {
  try {
    const base = typeof window !== 'undefined' ? window.location.href : undefined
    const target = new URL(url, base)
    const selfOrigin = typeof window !== 'undefined' ? window.location.origin : null
    let apiOrigin = null
    try { apiOrigin = new URL(apiUrl('/'), base).origin } catch { apiOrigin = null }
    return target.origin === selfOrigin || (apiOrigin != null && target.origin === apiOrigin)
  } catch {
    return false
  }
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
async function doRefreshToken() {
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

// Single-flight guard: when several requests (and the SSE/WS streams) all 401 at
// once on an expired token, they must share ONE refresh. Otherwise, with refresh
// -token rotation, the first call rotates the cookie and the rest present the
// now-consumed token, fail, and trigger a spurious logout (refresh stampede).
let refreshPromise = null
export async function tryRefreshToken() {
  if (refreshPromise) return refreshPromise
  refreshPromise = doRefreshToken().finally(() => {
    refreshPromise = null
  })
  return refreshPromise
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
    // Never leak the bearer token to a foreign origin: only attach it to
    // same-origin or the configured API-origin requests. Relative paths always
    // resolve to one of those; a hostile absolute URL would not.
    if (ah.Authorization && isSameApiOrigin(url)) headers.set('Authorization', ah.Authorization)
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

/** Clean SSE path — auth is header/cookie only, never query-string tokens. */
export function apiSseUrl(pathWithQuery) {
  const p = pathWithQuery.startsWith('/') ? pathWithQuery : `/${pathWithQuery}`
  return apiUrl(p)
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
