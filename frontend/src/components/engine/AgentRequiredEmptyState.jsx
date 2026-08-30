import { useTranslation } from 'react-i18next'
import { MonitorDown } from 'lucide-react'
import EmptyState from '../ui/EmptyState'
import AgentQueuePanel from './AgentQueuePanel'

/**
 * Shown for agent_required engines when no Weissman endpoint agent is connected.
 * Honest queue — no simulated findings.
 */
export default function AgentRequiredEmptyState({ engineId, clientId, className = '' }) {
  const { t } = useTranslation()

  return (
    <div className={`space-y-4 ${className}`}>
      <AgentQueuePanel engineId={engineId} clientId={clientId} />
      <EmptyState
        icon={<MonitorDown className="w-7 h-7 text-amber-400/90" strokeWidth={1.5} />}
        title={t('agentRequired.empty_title')}
        body={[t('agentRequired.empty_body'), t('agentRequired.install_hint')].join(' ')}
        cta={{
          label: t('agentRequired.install_cta'),
          to: '/agents',
        }}
      />
    </div>
  )
}
