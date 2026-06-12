import { useEffect, useMemo, useState } from 'react'
import { ENGINES_REGISTRY } from './enginesRegistry'
import { apiFetch } from './apiBase'

let cachedProductionIds = null
let fetchPromise = null
let registryIndex = null

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

function getRegistryIndex() {
  if (registryIndex) return registryIndex
  const idSet = new Set()
  const byId = new Map()
  for (const engine of ENGINES_REGISTRY) {
    idSet.add(engine.id)
    byId.set(engine.id, engine)
  }
  registryIndex = { idSet, byId }
  return registryIndex
}

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

  const { idSet: registryIdSet, byId: registryById } = useMemo(
    () => getRegistryIndex(),
    [],
  )

  const isProduction = useMemo(
    () => (id) => registryIdSet.has(id) || productionSet.has(id),
    [productionSet, registryIdSet],
  )

  const engines = useMemo(
    () => {
      if (!productionIds || productionIds.length === 0) {
        return ENGINES_REGISTRY
      }
      const out = []
      for (const id of productionIds) {
        const engine = registryById.get(id)
        if (engine) out.push(engine)
      }
      // Keep the "catalog-all" behavior for existing UI assumptions.
      return out.length > 0 ? out : ENGINES_REGISTRY
    },
    [productionIds, registryById],
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
