import { useCallback, useEffect, useMemo, useState } from 'react'
import { apiFetch } from './apiBase'
import { loadEnginesRegistry, prefetchEnginesRegistry } from './enginesRegistryLoader'

let cachedProductionIds = null
let fetchPromise = null

export function invalidateProductionEnginesCache() {
  cachedProductionIds = null
  fetchPromise = null
}

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

/**
 * Registry entries backed by live engine probes (GET /api/engines/production).
 * Full catalog loads in isolated `data-engines-registry` micro-chunk.
 */
export function useProductionEngines({ prefetch = false } = {}) {
  const [productionIds, setProductionIds] = useState(cachedProductionIds)
  const [loading, setLoading] = useState(!cachedProductionIds)
  const [registry, setRegistry] = useState(null)

  useEffect(() => {
    if (prefetch) prefetchEnginesRegistry()
    let cancelled = false
    loadEnginesRegistry().then((mod) => {
      if (!cancelled) setRegistry(mod)
    }).catch(() => {
      if (!cancelled) setRegistry(null)
    })
    return () => {
      cancelled = true
    }
  }, [prefetch])

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

  const registryIndex = useMemo(() => {
    if (!registry?.ENGINES_REGISTRY) return { idSet: new Set(), byId: new Map() }
    const idSet = new Set()
    const byId = new Map()
    for (const engine of registry.ENGINES_REGISTRY) {
      idSet.add(engine.id)
      byId.set(engine.id, engine)
    }
    return { idSet, byId }
  }, [registry])

  const { idSet: registryIdSet, byId: registryById } = registryIndex

  const isProduction = useMemo(
    () => (id) => registryIdSet.has(id) || productionSet.has(id),
    [productionSet, registryIdSet],
  )

  const engines = useMemo(() => {
    const catalog = registry?.ENGINES_REGISTRY || []
    if (!productionIds || productionIds.length === 0) return catalog
    const out = []
    for (const id of productionIds) {
      const engine = registryById.get(id)
      if (engine) out.push(engine)
    }
    return out.length > 0 ? out : catalog
  }, [productionIds, registryById, registry])

  const catalogCount = useMemo(() => {
    const catalog = registry?.ENGINES_REGISTRY || []
    return catalog.filter((e) => !isProduction(e.id)).length
  }, [registry, isProduction])

  const refresh = useCallback(async () => {
    invalidateProductionEnginesCache()
    setLoading(true)
    const ids = await fetchProductionIds()
    setProductionIds(ids)
    setLoading(false)
  }, [])

  return {
    engines,
    productionIds: productionIds || [],
    productionCount: engines.length,
    catalogCount,
    loading: loading || !registry,
    registryReady: !!registry,
    isProduction,
    refresh,
    ENGINES_BY_ID: registry?.ENGINES_BY_ID || {},
  }
}
