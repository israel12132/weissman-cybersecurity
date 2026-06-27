import React from 'react'
import { Link } from 'react-router-dom'
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
  const { integrations, integrationsLoading } = useClientIntegrations(clientId)
  const readiness = computeEngineIntegrationReadiness(engineId, integrations)

  if (!engineId) return null

  const pct = readiness.percent
  const barColor = pct >= 100 ? '#22d3ee' : pct >= 50 ? '#fbbf24' : '#f87171'

  return (
    <div
      className={`rounded-xl border border-white/10 bg-gradient-to-r from-black/50 via-black/35 to-black/50 px-4 py-3 ${className}`}
      data-testid="engine-integrations-bar"
    >
      <div className="flex flex-wrap items-center justify-between gap-3">
        <div className="flex items-center gap-3 min-w-0">
          <div className="shrink-0">
            <div className="text-[10px] font-mono text-white/40 uppercase tracking-widest">
              {t('components.engineIntegrations.title', { defaultValue: 'Integration Readiness' })}
            </div>
            <div className="flex items-baseline gap-2 mt-0.5">
              <span className="text-lg font-semibold tabular-nums" style={{ color: barColor }}>
                {integrationsLoading ? '…' : `${pct}%`}
              </span>
              <span className="text-[10px] font-mono text-white/35 truncate max-w-[200px]">
                {clientId
                  ? t('components.engineIntegrations.client', { defaultValue: 'Client #{{id}}', id: clientId })
                  : t('components.engineIntegrations.no_client', { defaultValue: 'Select a client to prefill credentials' })}
              </span>
            </div>
          </div>
          {!compact && (
            <div className="hidden sm:block w-28 h-1.5 rounded-full bg-white/10 overflow-hidden">
              <div
                className="h-full rounded-full transition-all duration-500"
                style={{ width: `${pct}%`, backgroundColor: barColor }}
              />
            </div>
          )}
        </div>

        <div className="flex flex-wrap items-center gap-2">
          {readiness.chips.map((chip) => (
            <span
              key={chip.key}
              title={chip.ok ? chip.label : `${chip.label} — not configured`}
              className={`text-[10px] font-mono px-2 py-0.5 rounded border ${
                chip.ok
                  ? 'border-emerald-500/40 text-emerald-300/90 bg-emerald-500/10'
                  : 'border-white/15 text-white/40 bg-white/[0.03]'
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
              className="text-[10px] font-mono text-amber-300/90 hover:text-amber-200 border border-amber-500/30 rounded px-2 py-0.5"
            >
              {t('components.engineIntegrations.configure', { defaultValue: 'Configure →' })}
            </Link>
          )}
          {engineId && (
            <Link
              to={`/engines/${engineId}`}
              className="text-[10px] font-mono text-cyan-300/90 hover:text-cyan-200 border border-cyan-500/30 rounded px-2 py-0.5"
            >
              {t('components.engineIntegrations.engine_detail', { defaultValue: 'Engine Detail →' })}
            </Link>
          )}
        </div>
      </div>
      {!readiness.ready && clientId && !integrationsLoading && readiness.chips.length > 0 && (
        <p className="mt-2 text-[10px] font-mono text-amber-400/80 leading-snug">
          {t('components.engineIntegrations.hint', {
            defaultValue: 'Missing integrations are hydrated server-side when configured; complete client setup for full live coverage.',
          })}
        </p>
      )}
    </div>
  )
}
