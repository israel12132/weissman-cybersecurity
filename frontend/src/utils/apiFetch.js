/**
 * JSON-oriented API client built on lib/apiBase (apiUrl, auth, token refresh).
 * 429 toast handling shares the same callback registered by RateLimitProvider
 * via lib/apiBase so both API clients show the same global rate-limit toast.
 */

import { apiFetch as baseApiFetch, setRateLimitToastCallback } from '../lib/apiBase.js'

export { setRateLimitToastCallback }

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

async function readErrorMessage(response) {
  let errorMessage = `HTTP ${response.status}: ${response.statusText}`
  try {
    const errorData = await response.clone().json()
    errorMessage = errorData.detail || errorData.message || errorData.error || errorMessage
  } catch {
    // ignore JSON parse errors
  }
  return errorMessage
}

/**
 * Fetch JSON from API paths (relative or absolute). Throws on non-OK responses.
 */
export async function apiFetch(url, options = {}) {
  const {
    method = 'GET',
    body,
    headers = {},
    credentials = 'include',
    // Explicit binary/raw bypass: when true, a 2xx response is returned unparsed
    // (the caller reads .blob()/.text()/.headers itself) instead of relying on the
    // content-type sniff below. Used by PDF/CSV downloads and by tolerant-parse
    // callers (e.g. useApiQuery) that must not throw on an empty/malformed body.
    raw = false,
    retries = 0,
    retryDelay = 1000,
    ...restOptions
  } = options

  const finalHeaders = { ...headers }
  const init = {
    method,
    headers: finalHeaders,
    credentials,
    ...restOptions,
  }

  if (body != null && typeof body === 'object' && !(body instanceof FormData)) {
    if (!finalHeaders['Content-Type'] && !finalHeaders['content-type']) {
      init.headers = { ...finalHeaders, 'Content-Type': 'application/json' }
    }
    init.body = JSON.stringify(body)
  } else if (body != null) {
    init.body = body
  }

  try {
    const response = await baseApiFetch(url, init)

    if (response.status === 429) {
      // The underlying lib/apiBase.apiFetch already fired the shared rate-limit
      // toast for this 429 (apiBase.js ~line 226). Do NOT fire it again here, or
      // every rate-limited request double-toasts. Attach the Response so catch-side
      // formatters (formatApiErrorResponse/formatHttpApiError/formatApiErrorFromBody)
      // can read the body, exactly like any other non-ok error below.
      const retryAfter = parseRetryAfter(response.headers.get('Retry-After'))
      const errorMessage = await readErrorMessage(response)
      const error = new Error(errorMessage)
      error.status = 429
      error.retryAfter = retryAfter
      error.response = response
      throw error
    }

    if (!response.ok) {
      const errorMessage = await readErrorMessage(response)
      const error = new Error(errorMessage)
      error.status = response.status
      error.response = response
      throw error
    }

    if (raw) return response

    const contentType = response.headers.get('content-type') || ''
    if (contentType.includes('application/json')) {
      return await response.json()
    }

    return response
  } catch (error) {
    if (error.status !== 429 && retries > 0) {
      await new Promise((resolve) => setTimeout(resolve, retryDelay))
      return apiFetch(url, {
        ...options,
        retries: retries - 1,
        retryDelay: retryDelay * 2,
      })
    }
    throw error
  }
}

export const api = {
  get: (url, options = {}) => apiFetch(url, { ...options, method: 'GET' }),
  post: (url, body, options = {}) => apiFetch(url, { ...options, method: 'POST', body }),
  put: (url, body, options = {}) => apiFetch(url, { ...options, method: 'PUT', body }),
  patch: (url, body, options = {}) => apiFetch(url, { ...options, method: 'PATCH', body }),
  delete: (url, options = {}) => apiFetch(url, { ...options, method: 'DELETE' }),
}

export default apiFetch
