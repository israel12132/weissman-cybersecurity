import { useAgentRequiredGate } from '../../hooks/useAgentRequiredGate'
import AgentQueuePanel from './AgentQueuePanel'
import { useEngineHub } from '../../context/EngineHubContext'

/**
 * For agent-required engines, show the live queue (never invented findings)
 * and keep run controls available so operators can enqueue for the next agent.
 */
export default function AgentRequiredGate({ engineId, clientId, children, className = '' }) {
  const { loading, isAgentRequired } = useAgentRequiredGate(engineId)
  const hub = useEngineHub()
  const resolvedClient = clientId ?? hub?.hubClientId

  if (!engineId) return children

  if (loading && isAgentRequired) {
    return (
      <div className={`rounded-2xl border border-[var(--border-subtle)] bg-[var(--row-hover-bg)] p-10 animate-pulse ${className}`}>
        <div className="h-4 w-48 bg-[var(--row-hover-bg)] rounded mb-3" />
        <div className="h-3 w-full max-w-md bg-[var(--row-hover-bg)] rounded" />
      </div>
    )
  }

  if (!isAgentRequired) return children

  return (
    <div className={`space-y-4 ${className}`}>
      <AgentQueuePanel engineId={engineId} clientId={resolvedClient} />
      {children}
    </div>
  )
}
