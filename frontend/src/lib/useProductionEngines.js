import { useEffect, useMemo, useState } from 'react'
import { ENGINES_REGISTRY } from './enginesRegistry'

let cachedProductionIds = null
let fetchPromise = null

async function fetchProductionIds() {
  if (cachedProductionIds) return cachedProductionIds
  if (!fetchPromise) {
    fetchPromise = fetch('/api/engines/production', { credentials: 'include' })
      .then((r) => (r.ok ? r.json() : null))
      .then((data) => {
        const ids = Array.isArray(data?.production) ? data.production : null
        cachedProductionIds = ids
        return ids
      })
      .catch(() => null)
      .finally(() => {
        fetchPromise = null
      })
  }
  return fetchPromise
}

/**
 * Registry entries backed by live engine probes (from GET /api/engines/production).
 */
export function useProductionEngines() {
  const [productionIds, setProductionIds] = useState(cachedProductionIds)
  const [loading, setLoading] = useState(!cachedProductionIds)

  useEffect(() => {
    if (cachedProductionIds) {
      setProductionIds(cachedProductionIds)
      setLoading(false)
      return
    }
    let cancelled = false
    fetchProductionIds().then((ids) => {
      if (cancelled) return
      setProductionIds(ids)
      setLoading(false)
    })
    return () => {
      cancelled = true
    }
  }, [])

  const productionSet = useMemo(
    () => new Set(productionIds || []),
    [productionIds],
  )

  const engines = useMemo(() => {
    if (!productionIds?.length) return ENGINES_REGISTRY
    return ENGINES_REGISTRY.filter((e) => productionSet.has(e.id))
  }, [productionIds, productionSet])

  return {
    engines,
    productionIds: productionIds || [],
    productionCount: productionIds?.length ?? 0,
    catalogCount: ENGINES_REGISTRY.length,
    loading,
    isProduction: (id) => productionSet.has(id),
  }
}
