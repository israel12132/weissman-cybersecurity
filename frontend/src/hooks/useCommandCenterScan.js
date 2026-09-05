import { useCallback } from 'react'
import { useEngineHub, useRegisterHubClient } from '../context/EngineHubContext'
import { useClientOptional } from '../context/ClientContext'
import { postEngineScan } from '../lib/launchEngineScan'
import { useClientIntegrations } from './useClientIntegrations'

/**
 * Integrations + postScan for Command Center hubs.
 * Merges PageShell hub params before POST (hub fields overridden by explicit body keys).
 * Scoped/portal users are force-bound to their assigned client + domain.
 */
export function useCommandCenterScan(clientId) {
  const ctx = useClientOptional()
  const locked = ctx?.clientScopeLocked === true
  const effectiveClientId = locked && ctx?.selectedClientId != null
    ? ctx.selectedClientId
    : clientId

  useRegisterHubClient(effectiveClientId)

  const { hubExtraParams, hubEngineId } = useEngineHub()
  const { integrations, integrationsLoading } = useClientIntegrations(effectiveClientId)

  const selectedClient = ctx?.clients?.find((c) => String(c.id) === String(effectiveClientId))
    ?? ctx?.selectedClient
    ?? null

  const postScan = useCallback(
    (customBody) => {
      const engine = customBody?.engine
      const shouldMergeHub =
        Object.keys(hubExtraParams).length > 0
        && (!hubEngineId || !engine || String(engine) === String(hubEngineId))
      const merged = shouldMergeHub
        ? { ...hubExtraParams, ...(customBody || {}) }
        : { ...(customBody || {}) }
      if (engine) merged.engine = customBody.engine
      if (effectiveClientId != null && effectiveClientId !== '') {
        merged.client_id = Number(effectiveClientId)
      }
      return postEngineScan(merged, integrations, {
        client: selectedClient,
        clientScopeLocked: locked,
      })
    },
    [integrations, hubExtraParams, hubEngineId, effectiveClientId, selectedClient, locked],
  )

  return {
    integrations,
    integrationsLoading,
    postScan,
    hubExtraParams,
    effectiveClientId,
    clientScopeLocked: locked,
  }
}
