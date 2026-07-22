import { useQuery } from '@tanstack/react-query'
import { apiFetch } from '../utils/apiFetch'

/**
 * Shared server-state hook over the app's `apiFetch`. Gives every dashboard request
 * de-duplication, caching, retry/backoff and stale-while-revalidate for free, replacing the
 * hand-rolled `useEffect` + `useState(loading/err/data)` loops each page currently re-implements.
 *
 * Treats a 404 as "empty" (`null`) rather than an error, matching the app's convention.
 *
 * @param {Array} key            react-query cache key (e.g. ['agents','status'])
 * @param {string} path          API path passed to apiFetch
 * @param {object} [opts]        { transform, enabled, refetchInterval, ...react-query options }
 * @param {(data:any)=>any} [opts.transform] map/normalise the parsed JSON before caching
 */
export function useApiQuery(key, path, opts = {}) {
  const { transform, ...queryOpts } = opts
  return useQuery({
    queryKey: key,
    queryFn: async () => {
      try {
        // raw:true so utils NEVER parses (and never throws a SyntaxError on an
        // empty/malformed body) — a 2xx always resolves to the Response and we
        // reproduce the original tolerant text→JSON parse (empty/malformed → null).
        // Non-2xx still throws (handled below); raw only affects the success path.
        const res = await apiFetch(path, { raw: true })
        const txt = await res.text()
        let data
        try {
          data = txt ? JSON.parse(txt) : null
        } catch {
          data = null
        }
        return transform ? transform(data) : data
      } catch (e) {
        // 404 is "empty", not an error — preserve the transform(null)/null contract.
        if (e?.status === 404) return transform ? transform(null) : null
        // Non-404 HTTP error: rebuild the original message contract
        // (body.detail || body.error || `HTTP <status>`) from the failed Response.
        if (e?.response) {
          const body = await e.response.json().catch(() => null)
          const detail = (body && (body.detail || body.error)) || `HTTP ${e.status}`
          throw new Error(detail)
        }
        // Network / 429 (no Response attached) — surface as-is.
        throw e
      }
    },
    ...queryOpts,
  })
}
