import { useMemo } from 'react'
import { useEngineCapabilities } from '../lib/useEngineCapabilities'
import { useAgentFleetStatus } from './useAgentFleetStatus'

/**
 * Derive gate states from live fleet + capabilities.
 *
 * `blocked` is only true when the fleet endpoint answered and reported zero
 * online agents. An unreachable status API is `unknown`, never "no agents".
 */
export function evaluateAgentRequiredGate({
  engineId,
  isAgentRequired,
  fleetLoading,
  fleetUnavailable,
  hasOnlineAgent,
}) {
  const waiting = Boolean(engineId && isAgentRequired && fleetLoading)
  const unknown = Boolean(
    engineId && isAgentRequired && !fleetLoading && fleetUnavailable && !hasOnlineAgent,
  )
  const blocked = Boolean(
    engineId && isAgentRequired && !fleetLoading && !fleetUnavailable && !hasOnlineAgent,
  )
  return { waiting, unknown, blocked }
}

/**
 * Blocks agent-required engine surfaces when no endpoint agent is online.
 * Returns honest empty-state signal — never fabricates findings, never treats
 * a down fleet API as an empty roster.
 */
export function useAgentRequiredGate(engineId) {
  const { byId, loading: capsLoading } = useEngineCapabilities()
  const {
    hasOnlineAgent,
    onlineCount,
    loading: fleetLoading,
    unavailable: fleetUnavailable,
    error: fleetError,
    refresh,
  } = useAgentFleetStatus()

  const cap = engineId ? byId[engineId] : null
  const isAgentRequired = cap?.kind === 'agent_required' || cap?.remote_detection === false

  const { waiting, unknown, blocked } = useMemo(
    () =>
      evaluateAgentRequiredGate({
        engineId,
        isAgentRequired,
        fleetLoading,
        fleetUnavailable,
        hasOnlineAgent,
      }),
    [engineId, isAgentRequired, fleetLoading, fleetUnavailable, hasOnlineAgent],
  )

  return {
    blocked,
    fleetUnavailable: unknown,
    waiting,
    isAgentRequired,
    hasOnlineAgent,
    onlineCount,
    loading: capsLoading || fleetLoading,
    fleetError,
    refresh,
    engineLabel: cap?.id || engineId,
  }
}
