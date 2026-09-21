import { Link } from 'react-router'
import { useTranslation } from 'react-i18next'
import { useClientIntegrations } from '../../hooks/useClientIntegrations'
import { computeEngineIntegrationReadiness } from '../../lib/engineIntegrationReadiness'

/**
 * Live integration readiness strip for command-center hubs.
 * Auto-registers hub client via useCommandCenterScan → EngineHubContext.
 */
export default function EngineIntegrationsBar({
  engineId,
  clientId,
  className = '',
  compact = false,
}) {
  const { t } = useTranslation()
  const { integrations, integrationsLoading, integrationsUnavailable } = useClientIntegrations(clientId)
  const readiness = computeEngineIntegrationReadiness(engineId, integrations)

  if (!engineId) return null

  const pct = readiness.percent
  const barColor = integrationsUnavailable
    ? 'var(--text-muted)'
    : pct >= 100 ? '#22d3ee' : pct >= 50 ? '#fbbf24' : '#f87171'

  return (
    <div
      className={`rounded-xl border border-[var(--border-default)] bg-gradient-to-r from-black/50 via-black/35 to-black/50 px-4 py-3 ${className}`}
      data-testid="engine-integrations-bar"
    >
      <div className="flex flex-wrap items-center justify-between gap-3">
        <div className="flex items-center gap-3 min-w-0">
          <div className="shrink-0">
            <div className="text-[10px] font-mono text-[var(--text-muted)] uppercase tracking-widest">
              {t('components.engineIntegrations.title')}
            </div>
            <div className="flex items-baseline gap-2 mt-0.5">
              <span className="text-lg font-semibold tabular-nums" style={{ color: barColor }}>
                {integrationsUnavailable ? '—' : integrationsLoading ? '…' : `${pct}%`}
              </span>
              <span className="text-[10px] font-mono text-[var(--text-muted)] truncate max-w-[200px]">
                {clientId
                  ? t('components.engineIntegrations.client', { id: clientId })
                  : t('components.engineIntegrations.no_client')}
              </span>
            </div>
          </div>
          {!compact && (
            <div className="hidden sm:block w-28 h-1.5 rounded-full bg-[var(--row-hover-bg)] overflow-hidden">
              <div
                className="h-full rounded-full transition-all duration-500"
                style={{ width: integrationsUnavailable ? '0%' : `${pct}%`, backgroundColor: barColor }}
              />
            </div>
          )}
        </div>

        <div className="flex flex-wrap items-center gap-2">
          {!integrationsUnavailable && readiness.chips.map((chip) => (
            <span
              key={chip.key}
              title={chip.ok ? chip.label : `${chip.label} — not configured`}
              className={`text-[10px] font-mono px-2 py-0.5 rounded border ${
                chip.ok
                  ? 'border-emerald-500/40 text-[var(--severity-low)] bg-emerald-500/10'
                  : 'border-[var(--border-strong)] text-[var(--text-muted)] bg-[var(--row-hover-bg)]'
              }`}
            >
              {chip.ok ? '✓' : '○'}
              {' '}
              {chip.label}
            </span>
          ))}
          {clientId && (
            <Link
              to={`/clients/${clientId}/integrations`}
              className="text-[10px] font-mono text-[var(--severity-medium)] hover:text-[var(--severity-medium)] border border-amber-500/30 rounded px-2 py-0.5"
            >
              {t('components.engineIntegrations.configure')}
            </Link>
          )}
          {engineId && (
            <Link
              to={`/engines/${engineId}`}
              className="text-[10px] font-mono text-[var(--text-accent)] hover:text-[var(--text-accent)] border border-cyan-500/30 rounded px-2 py-0.5"
            >
              {t('components.engineIntegrations.engine_detail')}
            </Link>
          )}
        </div>
      </div>
      {integrationsUnavailable && (
        <p data-testid="engine-integrations-unavailable" className="mt-2 text-[10px] font-mono text-[var(--severity-critical)] leading-snug">
          {t('components.engineIntegrations.unavailable')}
        </p>
      )}
      {!integrationsUnavailable && !readiness.ready && clientId && !integrationsLoading && readiness.chips.length > 0 && (
        <p className="mt-2 text-[10px] font-mono text-[var(--severity-medium)] leading-snug">
          {t('components.engineIntegrations.hint')}
        </p>
      )}
    </div>
  )
}
