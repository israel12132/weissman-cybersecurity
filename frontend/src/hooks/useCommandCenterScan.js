import { useCallback } from 'react'
import { useEngineHub, useRegisterHubClient } from '../context/EngineHubContext'
import { postEngineScan } from '../lib/launchEngineScan'
import { useClientIntegrations } from './useClientIntegrations'

/**
 * Integrations + postScan for Command Center hubs.
 * Merges PageShell hub params before POST (hub fields overridden by explicit body keys).
 */
export function useCommandCenterScan(clientId) {
  useRegisterHubClient(clientId)

  const { hubExtraParams, hubEngineId } = useEngineHub()
  const { integrations, integrationsLoading } = useClientIntegrations(clientId)

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
      return postEngineScan(merged, integrations)
    },
    [integrations, hubExtraParams, hubEngineId],
  )

  return { integrations, integrationsLoading, postScan, hubExtraParams }
}
