import { useCallback, useEffect, useMemo, useState } from 'react'
import { getEngineParams } from '../lib/engineParamDefs.js'
import { buildDefaultEngineParams, prefillParamsForEngine } from '../lib/engineClientPrefill'

/**
 * Manages engine parameter state with client-integration prefill.
 */
export function useEngineScanParams(engineId, clientIntegrations = null) {
  const schema = useMemo(() => (engineId ? getEngineParams({ id: engineId }) : []), [engineId])

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

  return { schema, extraParams, setParam, setExtraParams, resetParams }
}
