import { useTranslation } from 'react-i18next'
import { MonitorDown } from 'lucide-react'
import EmptyState from '../ui/EmptyState'

/**
 * Shown for agent_required engines when no Weissman endpoint agent is connected.
 * No simulated findings — operator must install the agent first.
 */
export default function AgentRequiredEmptyState({ engineId, className = '' }) {
  const { t } = useTranslation()

  const body = [
    t('agentRequired.empty_body', {
      defaultValue:
        'You must install the Weissman Agent on your endpoint to view this data. Remote scans cannot observe host-local signals for this engine.',
    }),
    engineId
      ? `${t('agentRequired.engine_id', { defaultValue: 'Engine' })}: ${engineId}`
      : null,
    t('agentRequired.install_hint', {
      defaultValue:
        'Generate an enrollment token in Agent Management, run the install script on the target host, then refresh once the agent connects.',
    }),
  ]
    .filter(Boolean)
    .join(' ')

  return (
    <EmptyState
      className={className}
      icon={<MonitorDown className="w-7 h-7 text-amber-400/90" strokeWidth={1.5} />}
      title={t('agentRequired.empty_title', {
        defaultValue: 'Endpoint agent required',
      })}
      body={body}
      cta={{
        label: t('agentRequired.install_cta', { defaultValue: 'Open Agent Management' }),
        to: '/agents',
      }}
    />
  )
}
