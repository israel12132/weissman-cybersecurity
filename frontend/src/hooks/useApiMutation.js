import { useMutation, useQueryClient } from '@tanstack/react-query'
import { apiFetch } from '../lib/apiBase'

/**
 * Server-state mutation hook over the app's `apiFetch`, with first-class
 * optimistic updates. It runs the canonical React-Query optimistic flow so
 * callers don't re-implement it per action:
 *   1. onMutate  — cancel in-flight queries for the target key, snapshot the
 *      current cache, and apply `optimisticUpdate(prev, vars)` immediately so
 *      the UI reflects the change before the network round-trip.
 *   2. onError   — roll the snapshot back.
 *   3. onSettled — invalidate the key so the server truth reconciles the cache.
 *
 * Static endpoint:
 *   useApiMutation({ path: '/findings/bulk', method: 'PATCH',
 *     optimisticKey: ['findings'],
 *     optimisticUpdate: (prev, vars) => applyBulk(prev, vars) })
 * Per-variables endpoint:
 *   useApiMutation({ request: (vars) => ({ path: `/findings/${vars.id}`, method: 'PATCH', body: vars.patch }), ... })
 *
 * @param {object} opts
 * @param {string} [opts.path]                    static endpoint (used with method + body=variables)
 * @param {string} [opts.method='POST']           HTTP method for the static endpoint
 * @param {(vars)=>{path:string,method?:string,body?:any,headers?:object}} [opts.request]
 *        build the request from the mutation variables (overrides path/method)
 * @param {Array|((vars)=>Array)} [opts.optimisticKey]   query key to update + invalidate
 * @param {(prev:any, vars:any)=>any} [opts.optimisticUpdate]  produce the next cached value
 * @param {boolean} [opts.invalidate=true]        invalidate optimisticKey on settle
 * @param {Function} [opts.onSuccess] @param {Function} [opts.onError] @param {Function} [opts.onSettled]
 * @returns {import('@tanstack/react-query').UseMutationResult}
 */
export function useApiMutation(opts = {}) {
  const queryClient = useQueryClient()
  const {
    path,
    method = 'POST',
    request,
    optimisticKey,
    optimisticUpdate,
    invalidate = true,
    onMutate,
    onSuccess,
    onError,
    onSettled,
    ...mutationOpts
  } = opts

  const resolveKey = (vars) =>
    typeof optimisticKey === 'function' ? optimisticKey(vars) : optimisticKey

  return useMutation({
    mutationFn: async (vars) => {
      const req = request ? request(vars) : { path, method, body: vars }
      const { path: reqPath, method: reqMethod = method, body, headers } = req
      const init = { method: reqMethod }
      if (body !== undefined && body !== null) {
        init.body = typeof body === 'string' ? body : JSON.stringify(body)
        init.headers = { 'Content-Type': 'application/json', ...(headers || {}) }
      } else if (headers) {
        init.headers = headers
      }
      const r = await apiFetch(reqPath, init)
      const txt = await r.text()
      let data = null
      try {
        data = txt ? JSON.parse(txt) : null
      } catch {
        data = txt || null
      }
      if (!r.ok) {
        const detail = (data && (data.detail || data.error)) || `HTTP ${r.status}`
        throw new Error(detail)
      }
      return data
    },
    onMutate: async (vars) => {
      // Caller hook runs first so it can extend the rollback context if desired.
      const extra = onMutate ? await onMutate(vars) : undefined
      if (!optimisticKey || !optimisticUpdate) return extra
      const key = resolveKey(vars)
      await queryClient.cancelQueries({ queryKey: key })
      const previous = queryClient.getQueryData(key)
      queryClient.setQueryData(key, (prev) => optimisticUpdate(prev, vars))
      return { ...(extra || {}), __optimisticKey: key, __previous: previous }
    },
    onError: (err, vars, ctx) => {
      if (ctx && ctx.__optimisticKey !== undefined) {
        // When the key had no cached data, the snapshot is `undefined`, and
        // setQueryData(key, undefined) is a no-op in query-core (it refuses to
        // store undefined) — the fabricated optimistic value would survive the
        // error. Remove the entry instead so the rollback actually reverts it.
        if (ctx.__previous === undefined) {
          queryClient.removeQueries({ queryKey: ctx.__optimisticKey, exact: true })
        } else {
          queryClient.setQueryData(ctx.__optimisticKey, ctx.__previous)
        }
      }
      onError?.(err, vars, ctx)
    },
    onSuccess: (data, vars, ctx) => {
      onSuccess?.(data, vars, ctx)
    },
    onSettled: (data, err, vars, ctx) => {
      if (invalidate && optimisticKey) {
        queryClient.invalidateQueries({ queryKey: resolveKey(vars) })
      }
      onSettled?.(data, err, vars, ctx)
    },
    ...mutationOpts,
  })
}

export default useApiMutation
