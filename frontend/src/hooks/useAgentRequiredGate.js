import { useMemo } from 'react'
import { useEngineCapabilities } from '../lib/useEngineCapabilities'
import { useAgentFleetStatus } from './useAgentFleetStatus'

/**
 * Agent-required engine surfaces: live queue + run controls.
 * `blocked` is true when no endpoint agent is online — callers must still allow enqueue.
 */
export function useAgentRequiredGate(engineId) {
  const { byId, loading: capsLoading } = useEngineCapabilities()
  const { hasOnlineAgent, onlineCount, loading: fleetLoading } = useAgentFleetStatus()

  const cap = engineId ? byId[engineId] : null
  const isAgentRequired = cap?.kind === 'agent_required' || cap?.remote_detection === false

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
