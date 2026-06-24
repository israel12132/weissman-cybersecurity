import { useMemo } from 'react'
import { useEngineCapabilities } from '../lib/useEngineCapabilities'
import { useAgentFleetStatus } from './useAgentFleetStatus'

/**
 * Blocks agent-required engine surfaces when no endpoint agent is online.
 * Returns honest empty-state signal — never fabricates findings.
 */
export function useAgentRequiredGate(engineId) {
  const { byId, loading: capsLoading } = useEngineCapabilities()
  const { hasOnlineAgent, onlineCount, loading: fleetLoading } = useAgentFleetStatus()

  const cap = engineId ? byId[engineId] : null
  const isAgentRequired = cap?.kind === 'agent_required'

  const blocked = useMemo(
    () => Boolean(engineId && isAgentRequired && !fleetLoading && !hasOnlineAgent),
    [engineId, isAgentRequired, fleetLoading, hasOnlineAgent],
  )

  return {
    blocked,
    isAgentRequired,
    hasOnlineAgent,
    onlineCount,
    loading: capsLoading || fleetLoading,
    engineLabel: cap?.id || engineId,
  }
}
