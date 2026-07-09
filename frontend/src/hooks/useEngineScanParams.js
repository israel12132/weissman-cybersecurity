import { useCallback, useEffect, useState } from 'react';
import { getEngineParams, getEngineParamsAsync, prefetchEngineParamsForEngine } from '../lib/engineParamDefs.js'
import { buildDefaultEngineParams, prefillParamsForEngine } from '../lib/engineClientPrefill'

/**
 * Manages engine parameter state with client-integration prefill.
 * Generated param profiles load asynchronously in an isolated micro-chunk.
 */
export function useEngineScanParams(engineId, clientIntegrations = null) {
  const [schema, setSchema] = useState(() => (engineId ? getEngineParams({ id: engineId }) : []))
  const [paramsReady, setParamsReady] = useState(false)

  useEffect(() => {
    if (!engineId) {
      setSchema([])
      setParamsReady(true)
      return
    }
    let cancelled = false
    setParamsReady(false)
    prefetchEngineParamsForEngine(engineId)
    getEngineParamsAsync({ id: engineId }).then((resolved) => {
      if (cancelled) return
      setSchema(resolved)
      setParamsReady(true)
    })
    return () => {
      cancelled = true
    }
  }, [engineId])

  const [extraParams, setExtraParams] = useState(() =>
    buildDefaultEngineParams(engineId, clientIntegrations),
  )

  useEffect(() => {
    if (!engineId) return
    const base = buildDefaultEngineParams(engineId, clientIntegrations)
    setExtraParams(
      clientIntegrations
        ? prefillParamsForEngine(engineId, clientIntegrations, base)
        : base,
    )
  }, [engineId, clientIntegrations])

  const setParam = useCallback((key, val) => {
    setExtraParams((prev) => ({ ...prev, [key]: val }))
  }, [])

  const resetParams = useCallback(() => {
    const base = buildDefaultEngineParams(engineId, clientIntegrations)
    setExtraParams(
      clientIntegrations
        ? prefillParamsForEngine(engineId, clientIntegrations, base)
        : base,
    )
  }, [engineId, clientIntegrations])

  return { schema, extraParams, setParam, setExtraParams, resetParams, paramsReady }
}
