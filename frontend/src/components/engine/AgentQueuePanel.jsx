import { useTranslation } from 'react-i18next'
import { Link } from 'react-router'
import { MonitorDown, Radio, Timer } from 'lucide-react'
import { useAgentQueue } from '../../hooks/useAgentQueue'
import { useAgentFleetStatus } from '../../hooks/useAgentFleetStatus'

function statusTone(status) {
  if (status === 'pending') return 'text-amber-300 border-amber-500/40 bg-amber-500/10'
  if (status === 'running') return 'text-cyan-300 border-cyan-500/40 bg-cyan-500/10'
  if (status === 'done') return 'text-emerald-300 border-emerald-500/40 bg-emerald-500/10'
  if (status === 'failed' || status === 'expired') return 'text-rose-300 border-rose-500/40 bg-rose-500/10'
  return 'text-[var(--text-muted)] border-[var(--border-default)]'
}

/**
 * Live waiting-for-agent queue. Never presents invented host findings.
 */
export default function AgentQueuePanel({ engineId, clientId, className = '', compact = false }) {
  const { t } = useTranslation()
  const { hasOnlineAgent, onlineCount, loading: fleetLoading } = useAgentFleetStatus()
  const { tasks, waiting, pending, running, loading } = useAgentQueue({
    engineId,
    clientId,
    enabled: true,
  })

  const visible = tasks.filter((row) => row.status === 'pending' || row.status === 'running').slice(0, compact ? 4 : 12)

  return (
    <section
      className={`rounded-2xl border border-amber-500/25 bg-gradient-to-br from-amber-500/[0.07] via-black/30 to-black/50 p-5 ${className}`}
      data-testid="agent-queue-panel"
    >
      <div className="flex flex-wrap items-start justify-between gap-3">
        <div className="min-w-0 space-y-1">
          <div className="flex items-center gap-2">
            <MonitorDown className="w-4 h-4 text-amber-400" strokeWidth={1.75} />
            <h2 className="text-sm font-semibold text-white tracking-tight">
              {t('agentRequired.queue_title')}
            </h2>
            <span className="text-[10px] font-mono px-2 py-0.5 rounded border border-amber-500/30 text-amber-300/90">
              {t('agentRequired.waiting_count', { count: waiting })}
            </span>
          </div>
          <p className="text-xs text-[var(--text-tertiary)] leading-relaxed max-w-2xl">
            {hasOnlineAgent
              ? t('agentRequired.queue_online_body', { count: onlineCount })
              : t('agentRequired.queue_offline_body')}
          </p>
          {engineId && (
            <p className="text-[10px] font-mono text-[var(--text-muted)]">
              {t('agentRequired.engine_id')}: {engineId}
            </p>
          )}
        </div>
        <div className="flex items-center gap-2 shrink-0">
          <span className={`inline-flex items-center gap-1 text-[10px] font-mono px-2 py-1 rounded border ${
            hasOnlineAgent
              ? 'border-emerald-500/40 text-emerald-300 bg-emerald-500/10'
              : 'border-amber-500/40 text-amber-300 bg-amber-500/10'
          }`}>
            <Radio className={`w-3 h-3 ${hasOnlineAgent ? 'animate-pulse' : ''}`} />
            {fleetLoading
              ? t('agentRequired.fleet_loading')
              : hasOnlineAgent
                ? t('agentRequired.fleet_online', { count: onlineCount })
                : t('agentRequired.fleet_offline')}
          </span>
          <Link
            to="/agents"
            className="text-[11px] font-mono px-3 py-1.5 rounded-lg border border-amber-500/40 text-amber-200 hover:bg-amber-500/10"
          >
            {t('agentRequired.install_cta')}
          </Link>
        </div>
      </div>

      <div className="grid grid-cols-2 sm:grid-cols-4 gap-2 mt-4">
        <QueueKpi label={t('agentRequired.kpi_pending')} value={pending} tone="#f59e0b" />
        <QueueKpi label={t('agentRequired.kpi_running')} value={running} tone="#22d3ee" />
        <QueueKpi label={t('agentRequired.kpi_waiting')} value={waiting} tone="#fbbf24" />
        <QueueKpi
          label={t('agentRequired.kpi_live')}
          value={hasOnlineAgent ? onlineCount : 0}
          tone={hasOnlineAgent ? '#34d399' : '#94a3b8'}
        />
      </div>

      <div className="mt-4">
        {loading && visible.length === 0 ? (
          <div className="h-10 rounded-lg bg-[var(--row-hover-bg)] animate-pulse" />
        ) : visible.length === 0 ? (
          <p className="text-xs text-[var(--text-muted)] font-mono flex items-center gap-2">
            <Timer className="w-3.5 h-3.5" />
            {t('agentRequired.queue_empty')}
          </p>
        ) : (
          <ul className="space-y-2">
            {visible.map((row) => (
              <li
                key={row.task_id}
                className="flex flex-wrap items-center justify-between gap-2 rounded-lg border border-white/[0.06] bg-black/25 px-3 py-2"
              >
                <div className="min-w-0">
                  <div className="text-[11px] font-mono text-white truncate">{row.engine}</div>
                  <div className="text-[10px] font-mono text-[var(--text-muted)] truncate">
                    {row.target || '—'}
                    {row.scan_job_id ? ` · job ${String(row.scan_job_id).slice(0, 8)}` : ''}
                  </div>
                </div>
                <span className={`text-[10px] font-mono px-2 py-0.5 rounded border ${statusTone(row.status)}`}>
                  {row.status}
                </span>
              </li>
            ))}
          </ul>
        )}
      </div>

      {!hasOnlineAgent && (
        <p className="mt-3 text-[11px] text-amber-200/80 leading-relaxed">
          {t('agentRequired.install_hint')}
        </p>
      )}
    </section>
  )
}

function QueueKpi({ label, value, tone }) {
  return (
    <div className="rounded-xl border border-white/[0.06] bg-black/20 px-3 py-2">
      <div className="text-[10px] font-mono uppercase text-[var(--text-muted)]">{label}</div>
      <div className="text-lg font-bold tabular-nums" style={{ color: tone }}>{value}</div>
    </div>
  )
}

