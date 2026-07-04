import { useAgentRequiredGate } from '../../hooks/useAgentRequiredGate'
import AgentRequiredEmptyState from './AgentRequiredEmptyState'

/**
 * Renders children only when the engine is not agent-gated or an agent is online.
 * Otherwise shows a strict empty state (no mock / guidance findings).
 */
export default function AgentRequiredGate({ engineId, children, className = '' }) {
  const { blocked, loading, isAgentRequired } = useAgentRequiredGate(engineId)

  if (!engineId) return children

  // Only defer the surface while capabilities load for agent-gated engines.
  // Remote probes (OSINT, ASM, etc.) must stay runnable without waiting on fleet status.
  if (loading && isAgentRequired) {
    return (
      <div className={`rounded-2xl border border-white/[0.07] bg-white/[0.02] p-10 animate-pulse ${className}`}>
        <div className="h-4 w-48 bg-white/10 rounded mb-3" />
        <div className="h-3 w-full max-w-md bg-white/5 rounded" />
      </div>
    )
  }

  if (blocked) {
    return <AgentRequiredEmptyState engineId={engineId} className={className} />
  }

  return children
}
