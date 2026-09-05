import { useCallback, useEffect, useMemo } from 'react'
import { useEngineHub } from '../context/EngineHubContext'
import { useClientOptional } from '../context/ClientContext'
import { launchEngineScan } from '../lib/launchEngineScan'
import { useClientIntegrations } from './useClientIntegrations'

/** Push engineId + param state into EngineHubContext (profile pages with own panel). */
export function useSyncHubScanParams(engineId, extraParams) {
  const { setHubEngineId, setHubExtraParams } = useEngineHub()

  useEffect(() => {
    setHubEngineId(engineId || null)
    return () => setHubEngineId(null)
  }, [engineId, setHubEngineId])

  useEffect(() => {
    setHubExtraParams(extraParams || {})
  }, [extraParams, setHubExtraParams])

  useEffect(() => () => setHubExtraParams({}), [setHubExtraParams])
}

/** Sync buildBody() extras (minus engine/target/client_id) into hub context. */
export function useHubBodySync(engineId, buildBodyFn) {
  const hubScanParams = useMemo(() => {
    const body = buildBodyFn()
    const { engine, target, client_id, ...rest } = body
    return rest
  }, [buildBodyFn])
  useSyncHubScanParams(engineId, hubScanParams)
}

/** Focus PageShell integrations/params on a child engine inside multi-engine hubs. */
export function useHubEngineFocus(engineId, { active = true } = {}) {
  const { setHubEngineId } = useEngineHub()
  useEffect(() => {
    if (!active || !engineId) return undefined
    setHubEngineId(engineId)
    return () => setHubEngineId(null)
  }, [engineId, active, setHubEngineId])
}

/**
 * launchEngineScan with hub extraParams + client integrations merged in.
 * For EngineMatrix, EngineClientCatalog, OsintEngineProfile.
 */
export function useLaunchEngineScan(clientId) {
  const { hubExtraParams, hubEngineId } = useEngineHub()
  const { integrations } = useClientIntegrations(clientId)
  const clientCtx = useClientOptional()

  return useCallback(
    (opts = {}) => {
      const engine = opts.engineId ?? opts.engine
      const shouldMergeHub =
        Object.keys(hubExtraParams).length > 0
        && (!hubEngineId || !engine || String(engine) === String(hubEngineId))
      return launchEngineScan({
        ...opts,
        clientId: opts.clientId ?? clientId,
        integrations: opts.integrations ?? integrations,
        client: opts.client ?? clientCtx?.selectedClient ?? null,
        clientScopeLocked: opts.clientScopeLocked ?? clientCtx?.clientScopeLocked ?? false,
        extraParams: {
          ...(shouldMergeHub ? hubExtraParams : {}),
          ...(opts.extraParams || {}),
        },
      })
    },
    [clientId, hubExtraParams, hubEngineId, integrations, clientCtx],
  )
}
