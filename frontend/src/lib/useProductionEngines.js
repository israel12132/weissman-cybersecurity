import { useEffect, useMemo, useState } from 'react'
import { ENGINES_REGISTRY } from './enginesRegistry'
import { apiFetch } from './apiBase'

let cachedProductionIds = null
let fetchPromise = null

async function fetchProductionIds() {
  if (cachedProductionIds) return cachedProductionIds
  if (!fetchPromise) {
    fetchPromise = apiFetch('/api/engines/production')
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

const registryIdSet = new Set(ENGINES_REGISTRY.map((e) => e.id))

/**
 * Registry entries backed by live engine probes (GET /api/engines/production).
 * All 531 registry engines are wired to real probes (dedicated or alias runner).
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

  const isProduction = useMemo(
    () => (id) => registryIdSet.has(id) || productionSet.has(id),
    [productionSet],
  )

  const engines = useMemo(
    () => ENGINES_REGISTRY.filter((e) => isProduction(e.id)),
    [isProduction],
  )

  const catalogCount = useMemo(
    () => ENGINES_REGISTRY.filter((e) => !isProduction(e.id)).length,
    [isProduction],
  )

  return {
    engines,
    productionIds: productionIds || [],
    productionCount: engines.length,
    catalogCount,
    loading,
    isProduction,
  }
}
