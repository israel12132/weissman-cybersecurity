import { useQuery } from '@tanstack/react-query'
import { apiFetch } from '../lib/apiBase'

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
      const r = await apiFetch(path)
      if (r.status === 404) return transform ? transform(null) : null
      const txt = await r.text()
      let data = null
      try {
        data = txt ? JSON.parse(txt) : null
      } catch {
        data = null
      }
      if (!r.ok) {
        const detail = (data && (data.detail || data.error)) || `HTTP ${r.status}`
        throw new Error(detail)
      }
      return transform ? transform(data) : data
    },
    ...queryOpts,
  })
}
