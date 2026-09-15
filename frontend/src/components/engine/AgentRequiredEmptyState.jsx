import { useTranslation } from 'react-i18next'
import { MonitorDown, Unplug } from 'lucide-react'
import EmptyState from '../ui/EmptyState'

/**
 * Shown for agent_required engines when the fleet is known-empty or when fleet
 * status cannot be confirmed. No simulated findings — never claim "install an
 * agent" when we simply failed to reach GET /api/agents/status.
 */
export default function AgentRequiredEmptyState({
  engineId,
  className = '',
  unavailable = false,
  onRetry,
}) {
  const { t } = useTranslation()

  const body = unavailable
    ? [
        t('agentRequired.unavailable_body'),
        engineId ? `${t('agentRequired.engine_id')}: ${engineId}` : null,
        t('agentRequired.unavailable_hint'),
      ]
        .filter(Boolean)
        .join(' ')
    : [
        t('agentRequired.empty_body'),
        engineId ? `${t('agentRequired.engine_id')}: ${engineId}` : null,
        t('agentRequired.install_hint'),
      ]
        .filter(Boolean)
        .join(' ')

  return (
    <div
      className={className}
      data-testid="agent-required-empty"
      data-unavailable={unavailable ? 'true' : 'false'}
      data-live="false"
    >
      <EmptyState
        icon={
          unavailable ? (
            <Unplug className="w-7 h-7 text-amber-400/90" strokeWidth={1.5} />
          ) : (
            <MonitorDown className="w-7 h-7 text-amber-400/90" strokeWidth={1.5} />
          )
        }
        title={t(unavailable ? 'agentRequired.unavailable_title' : 'agentRequired.empty_title')}
        body={body}
        cta={
          unavailable
            ? typeof onRetry === 'function'
              ? { label: t('agentRequired.unavailable_cta'), onClick: onRetry }
              : { label: t('agentRequired.open_management'), to: '/agents' }
            : { label: t('agentRequired.install_cta'), to: '/agents' }
        }
        secondary={
          unavailable && typeof onRetry === 'function'
            ? { label: t('agentRequired.open_management'), to: '/agents' }
            : undefined
        }
      />
    </div>
  )
}
