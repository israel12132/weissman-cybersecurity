import { createContext, useCallback, useContext, useEffect, useMemo, useState } from 'react'
import {
  getManifestByRoute,
  getManifestByEngineId,
  loadEngineManifests,
  getAllManifests,
} from './engineManifestRegistry'

const EngineManifestContext = createContext(null)

export function EngineManifestProvider({ children }) {
  const [ready, setReady] = useState(false)
  const [error, setError] = useState(null)

  const refresh = useCallback(async () => {
    try {
      await loadEngineManifests(true)
      setError(null)
    } catch (e) {
      setError(e?.message || 'manifest load failed')
    } finally {
      setReady(true)
    }
  }, [])

  useEffect(() => {
    let cancelled = false
    loadEngineManifests(false)
      .then(async () => {
        if (cancelled) return
        const { prefetchCapability } = await import('../boot/capabilityPrefetch')
        for (const m of getAllManifests()) {
          const c = m.capabilities || {}
          if (c.requires_ast_viewer) prefetchCapability('ast')
          if (c.requires_template_runner) prefetchCapability('registry')
        }
      })
      .finally(() => {
        if (!cancelled) setReady(true)
      })
    return () => {
      cancelled = true
    }
  }, [])

  const value = useMemo(
    () => ({
      ready,
      error,
      manifests: getAllManifests(),
      resolveByRoute: getManifestByRoute,
      resolveByEngineId: getManifestByEngineId,
      refresh,
    }),
    [ready, error, refresh],
  )

  return (
    <EngineManifestContext.Provider value={value}>
      {children}
    </EngineManifestContext.Provider>
  )
}

export function useEngineManifest() {
  const ctx = useContext(EngineManifestContext)
  if (!ctx) {
    return {
      ready: true,
      error: null,
      manifests: getAllManifests(),
      resolveByRoute: getManifestByRoute,
      resolveByEngineId: getManifestByEngineId,
      refresh: () => loadEngineManifests(true),
    }
  }
  return ctx
}

/** Resolve manifest for current route or explicit engine id override. */
export function useResolvedEngineManifest({ pathname, engineId }) {
  const { resolveByRoute, resolveByEngineId, ready } = useEngineManifest()
  return useMemo(() => {
    if (engineId) return resolveByEngineId(engineId)
    if (pathname) return resolveByRoute(pathname)
    return null
  }, [engineId, pathname, resolveByRoute, resolveByEngineId, ready])
}
