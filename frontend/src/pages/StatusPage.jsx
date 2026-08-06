import { useCallback, useEffect, useMemo, useRef, useState } from 'react'
import { Link } from 'react-router'
import { useTranslation } from 'react-i18next'
import {
  Activity,
  CheckCircle2,
  AlertTriangle,
  XCircle,
  Clock,
  Database,
  Server,
  Cpu,
  Radio,
} from 'lucide-react'
import { apiFetch } from '../utils/apiFetch'
import { apiUrl } from '../lib/apiBase'
import { useVisiblePolling } from '../hooks/useVisiblePolling'
import LanguageSwitcher from '../components/LanguageSwitcher'
import ShellScanActions from '../components/engine/ShellScanActions'
import WeissmanListToolbar from '../components/engine/WeissmanListToolbar'
import EvidenceNotice from '../components/ui/EvidenceNotice'

const STATUS = {
  operational: {
    dot: 'bg-emerald-400',
    ring: 'ring-emerald-400/30',
    glow: 'shadow-[0_0_16px_rgba(52,211,153,0.45)]',
    labelKey: 'status.operational',
    icon: CheckCircle2,
    iconClass: 'text-emerald-400',
    badge: 'bg-emerald-500/15 text-emerald-200 border-emerald-500/30',
  },
  degraded: {
    dot: 'bg-amber-400',
    ring: 'ring-amber-400/30',
    glow: 'shadow-[0_0_16px_rgba(251,191,36,0.4)]',
    labelKey: 'status.degraded',
    icon: AlertTriangle,
    iconClass: 'text-amber-400',
    badge: 'bg-amber-500/15 text-amber-200 border-amber-500/30',
  },
  outage: {
    dot: 'bg-rose-500',
    ring: 'ring-rose-500/30',
    glow: 'shadow-[0_0_16px_rgba(244,63,94,0.45)]',
    labelKey: 'status.outage',
    icon: XCircle,
    iconClass: 'text-rose-400',
    badge: 'bg-rose-500/15 text-rose-200 border-rose-500/30',
  },
  unknown: {
    dot: 'bg-white/30',
    ring: 'ring-white/10',
    glow: '',
    labelKey: 'status.checking',
    icon: Activity,
    iconClass: 'text-[var(--text-muted)]',
    badge: 'bg-[var(--row-hover-bg)] text-[var(--text-tertiary)] border-[var(--border-default)]',
  },
}

function fmtUptime(secs, t) {
  if (secs == null) return '—'
  const d = Math.floor(secs / 86400)
  const h = Math.floor((secs % 86400) / 3600)
  const m = Math.floor((secs % 3600) / 60)
  if (d > 0) return t('status.uptime_days', { days: d, hours: h })
  if (h > 0) return t('status.uptime_hours', { hours: h, minutes: m })
  return t('status.uptime_minutes', { minutes: m })
}

function fmtChecked(iso, locale) {
  if (!iso) return '—'
  try {
    return new Date(iso).toLocaleString(locale, {
      month: 'short',
      day: 'numeric',
      hour: '2-digit',
      minute: '2-digit',
      second: '2-digit',
    })
  } catch {
    return String(iso)
  }
}

function StatusIndicator({ level }) {
  const meta = STATUS[level] || STATUS.unknown
  return (
    <span className={`inline-block w-2.5 h-2.5 rounded-full ring-2 ${meta.dot} ${meta.ring} ${meta.glow}`} />
  )
}

function ServiceCard({ icon: Icon, name, description, level, detail, detailLink, checkedAt, t, locale }) {
  const meta = STATUS[level] || STATUS.unknown
  const StatusIcon = meta.icon
  const detailContent = detailLink ? (
    <Link to={detailLink} className="text-xs font-mono text-cyan-300/90 hover:text-cyan-200 truncate underline-offset-2 hover:underline">
      {detail || '—'}
    </Link>
  ) : (
    <span className="text-xs font-mono text-[var(--text-secondary)] truncate">{detail || '—'}</span>
  )
  return (
    <article className="rounded-2xl border border-[var(--border-default)] bg-[var(--table-surface)] backdrop-blur-md p-5 hover:border-[var(--border-strong)] transition-colors">
      <div className="flex items-start justify-between gap-3 mb-4">
        <div className="flex items-center gap-3 min-w-0">
          <div className="flex h-10 w-10 shrink-0 items-center justify-center rounded-xl border border-[var(--border-default)] bg-[var(--row-hover-bg)]">
            <Icon className="h-5 w-5 text-cyan-400/90" />
          </div>
          <div className="min-w-0">
            <h3 className="text-sm font-semibold text-[var(--text-primary)] truncate">{name}</h3>
            <p className="text-xs text-[var(--text-muted)] mt-0.5 line-clamp-2">{description}</p>
          </div>
        </div>
        <div className={`inline-flex items-center gap-1.5 shrink-0 px-2.5 py-1 rounded-full border text-[10px] font-mono uppercase tracking-wide ${meta.badge}`}>
          <StatusIndicator level={level} />
          {t(meta.labelKey)}
        </div>
      </div>
      <div className="flex items-end justify-between gap-3 pt-3 border-t border-[var(--border-subtle)]">
        <div className="flex items-center gap-2 min-w-0">
          <StatusIcon className={`h-4 w-4 shrink-0 ${meta.iconClass}`} />
          {detailContent}
        </div>
        {checkedAt && (
          <span className="text-[10px] font-mono text-[var(--text-disabled)] whitespace-nowrap flex items-center gap-1">
            <Clock className="h-3 w-3" />
            {fmtChecked(checkedAt, locale)}
          </span>
        )}
      </div>
    </article>
  )
}

function deriveServices(state, t) {
  const ts = state.ts
  const services = []

  const apiLevel = state.loading
    ? 'unknown'
    : state.api?.ok
    ? 'operational'
    : 'outage'
  services.push({
    id: 'api',
    icon: Server,
    level: apiLevel,
    detail: state.api
      ? state.api.ok
        ? t('status.detail_api_ok', { status: state.api.status, ms: state.api.latency_ms })
        : state.api.error || t('status.detail_api_fail', { status: state.api.status || 0 })
      : null,
    checkedAt: ts,
  })

  const dbLevel = state.loading
    ? 'unknown'
    : state.health?.postgres_ok === true
    ? 'operational'
    : state.health?.postgres_ok === false
    ? 'outage'
    : state.api?.ok
    ? 'degraded'
    : 'unknown'
  services.push({
    id: 'database',
    icon: Database,
    level: dbLevel,
    detail: state.health?.postgres_ok === true
      ? t('status.detail_db_ok')
      : state.health?.postgres_ok === false
      ? t('status.detail_db_fail')
      : state.api?.ok
      ? t('status.detail_db_missing')
      : null,
    checkedAt: ts,
  })

  const scanLevel = state.loading
    ? 'unknown'
    : !state.health
    ? 'unknown'
    : state.health.scan_in_progress
    ? 'degraded'
    : state.health.scanning_enabled
    ? 'operational'
    : 'degraded'
  services.push({
    id: 'scanning',
    icon: Activity,
    level: scanLevel,
    detail: state.health
      ? state.health.scan_in_progress
        ? t('status.detail_scan_active', { count: state.health.active_tenant_cycles ?? 0 })
        : state.health.scanning_enabled
        ? t('status.detail_scan_enabled')
        : t('status.detail_scan_paused')
      : null,
    checkedAt: ts,
  })

  const engineLevel = state.loading
    ? 'unknown'
    : state.engines?.ok
    ? 'operational'
    : state.engines
    ? 'outage'
    : 'unknown'
  services.push({
    id: 'engines',
    icon: Cpu,
    level: engineLevel,
    detail: state.engines?.ok
      ? t('status.detail_engines_ok', {
          production: state.engines.production_count,
          catalog: state.engines.catalog_count,
        })
      : state.engines?.error || (state.engines?.status ? t('status.detail_http', { status: state.engines.status }) : null),
    detailLink: state.engines?.ok ? '/engines?tier=live' : null,
    checkedAt: ts,
  })

  const agentLevel = state.loading
    ? 'unknown'
    : state.agents?.ok
    ? state.agents.online_visible === false
      ? 'operational'
      : state.agents.total > 0 && state.agents.online === 0
      ? 'degraded'
      : 'operational'
    : state.agents
    ? 'degraded'
    : 'unknown'
  services.push({
    id: 'agents',
    icon: Radio,
    level: agentLevel,
    detail: state.agents?.ok
      ? state.agents.online !== undefined
        ? t('status.detail_agents_online', { online: state.agents.online, total: state.agents.total })
        : state.agents.detail
      : state.agents?.error || (state.agents?.status ? t('status.detail_http', { status: state.agents.status }) : null),
    checkedAt: ts,
  })

  return services
}

function exportStatusCsv(state, t) {
  const services = deriveServices({ ...state, loading: false }, t)
  const header = ['id', 'level', 'detail', 'checked_at']
  const esc = (v) => `"${String(v ?? '').replace(/"/g, '""')}"`
  const lines = [
    header.join(','),
    ...services.map((svc) =>
      [svc.id, svc.level, svc.detail, svc.checkedAt].map(esc).join(','),
    ),
  ]
  const blob = new Blob([lines.join('\n')], { type: 'text/csv;charset=utf-8' })
  const url = URL.createObjectURL(blob)
  const a = document.createElement('a')
  a.href = url
  a.download = `weissman-status-${new Date().toISOString().slice(0, 10)}.csv`
  a.click()
  URL.revokeObjectURL(url)
}

function extractFailedHealthProbes(audit) {
  if (!audit || typeof audit !== 'object') return []
  if (Array.isArray(audit.failed_health_probes)) return audit.failed_health_probes
  if (Array.isArray(audit.last_failed_probes)) return audit.last_failed_probes

  const engines = Array.isArray(audit.engines) ? audit.engines : []
  return engines
    .filter((e) => {
      const probeStatus = e.probe_status || e.last_probe_status || e.health_probe?.status
      return probeStatus === 'fail' || probeStatus === 'failed'
    })
    .map((e) => ({
      engine_id: e.engine_id || e.id,
      message: e.health_probe?.message || e.probe_message || e.message || null,
      checked_at: e.health_probe?.checked_at || e.last_probe_at || e.checked_at,
    }))
}

function overallLevel(services, state) {
  if (state.loading) return 'unknown'
  if (services.some((s) => s.level === 'outage')) return 'outage'
  if (state.health?.global_safe_mode) return 'degraded'
  if (services.some((s) => s.level === 'degraded')) return 'degraded'
  if (services.every((s) => s.level === 'operational')) return 'operational'
  return 'degraded'
}

/**
 * Public status page — no auth required. Pings the API health endpoint, the production engine
 * registry, and the agent status. Used by customers + uptime monitors.
 */
export default function StatusPage() {
  const { t, i18n } = useTranslation()
  const [state, setState] = useState({
    loading: true,
    api: null,
    health: null,
    engines: null,
    agents: null,
    error: null,
    ts: null,
  })
  const [incidents, setIncidents] = useState([])
  const [failedProbes, setFailedProbes] = useState([])
  const [serviceSearch, setServiceSearch] = useState('')
  const prevLevels = useRef({})

  const recordIncidents = useCallback((services, ts) => {
    setIncidents((prev) => {
      const next = [...prev]
      for (const svc of services) {
        const prevLevel = prevLevels.current[svc.id]
        const cur = svc.level
        if (prevLevel && prevLevel !== cur) {
          if (cur === 'outage' || cur === 'degraded') {
            next.unshift({
              id: `${svc.id}-${ts}`,
              serviceId: svc.id,
              level: cur,
              startedAt: ts,
              resolvedAt: null,
              detail: svc.detail,
            })
          } else if (cur === 'operational') {
            const open = next.find((i) => i.serviceId === svc.id && !i.resolvedAt)
            if (open) open.resolvedAt = ts
          }
        }
        prevLevels.current[svc.id] = cur
      }
      return next.slice(0, 20)
    })
  }, [])

  const probe = useCallback(async () => {
    const ts = new Date().toISOString()
    const result = { loading: false, api: null, health: null, engines: null, agents: null, error: null, ts }

    const t0 = performance.now()
    try {
      const r = await fetch(apiUrl('/api/health'), { credentials: 'omit' })
      const latency = Math.round(performance.now() - t0)
      result.api = { ok: r.ok, status: r.status, latency_ms: latency }
      if (r.ok) {
        try {
          result.health = await r.json()
        } catch {
          result.health = null
        }
      }
    } catch (e) {
      result.api = { ok: false, status: 0, latency_ms: 0, error: e.message }
    }

    try {
      const r = await fetch(apiUrl('/api/engines/production'), { credentials: 'omit' })
      if (r.ok) {
        const d = await r.json()
        result.engines = {
          ok: true,
          production_count: d.production_count,
          catalog_count: d.catalog_count,
        }
      } else {
        result.engines = { ok: false, status: r.status }
      }
    } catch (e) {
      result.engines = { ok: false, error: e.message }
    }

    try {
      const r = await fetch(apiUrl('/api/engines/top-tier/audit'), { credentials: 'omit' })
      if (r.ok) {
        const audit = await r.json()
        setFailedProbes(extractFailedHealthProbes(audit))
      }
    } catch {
      // audit probe failures are optional on the public status page
    }

    try {
      const d = await apiFetch('/api/agents/status')
      // A 2xx with a non-JSON body (utils returns the raw Response) is NOT a
      // healthy signal on a status page — reproduce the old r.json()-throws path
      // so it lands in the catch as an error rather than a false "0 online".
      if (d instanceof Response) throw new Error('non-JSON status response')
      result.agents = {
        ok: true,
        total: d.agents?.length || 0,
        online: d.online_count || 0,
      }
    } catch (e) {
      if (e?.status === 401) {
        result.agents = { ok: true, online_visible: false, detail: t('status.agents_auth_required') }
      } else if (e?.status != null) {
        result.agents = { ok: false, status: e.status }
      } else {
        result.agents = { ok: false, error: e.message }
      }
    }

    setState(result)
    const services = deriveServices({ ...result, loading: false }, t)
    recordIncidents(services, ts)
  }, [recordIncidents, t])

  useEffect(() => {
    probe()
  }, [probe])

  // Re-probe every 30s, skipping ticks while the tab is hidden.
  useVisiblePolling(probe, 30_000)

  const services = deriveServices(state, t)

  // eslint-disable-next-line react-hooks/exhaustive-deps
  const serviceMeta = {
    api: { nameKey: 'status.api_auth', descKey: 'status.api_auth_desc' },
    database: { nameKey: 'status.database', descKey: 'status.database_desc' },
    scanning: { nameKey: 'status.scan_orchestrator', descKey: 'status.scan_orchestrator_desc' },
    engines: { nameKey: 'status.engine_registry', descKey: 'status.engine_registry_desc' },
    agents: { nameKey: 'status.endpoint_agents', descKey: 'status.endpoint_agents_desc' },
  }

  const filteredServices = useMemo(() => {
    const q = serviceSearch.trim().toLowerCase()
    if (!q) return services
    return services.filter((svc) => {
      const meta = serviceMeta[svc.id]
      const name = t(meta?.nameKey || 'status.components').toLowerCase()
      const desc = t(meta?.descKey || '').toLowerCase()
      return `${svc.id} ${name} ${desc} ${svc.level} ${svc.detail || ''}`.toLowerCase().includes(q)
    })
  }, [services, serviceSearch, t, serviceMeta])

  const overall = overallLevel(services, state)
  const overallMeta = STATUS[overall] || STATUS.unknown
  const OverallIcon = overallMeta.icon

  const visibleIncidents = incidents.filter((i) => i.level !== 'operational')
  const hasSafeMode = state.health?.global_safe_mode === true

  return (
    <div
      className="min-h-[100dvh] text-[var(--text-secondary)]"
      style={{ background: 'var(--shell-bg)' }}
    >
      <div className="max-w-4xl mx-auto px-4 sm:px-6 py-8 sm:py-12">
        <header className="mb-10">
          <div className="flex justify-between items-start gap-4 mb-6">
            <div className="flex items-center gap-3">
              <div className="flex h-11 w-11 items-center justify-center rounded-2xl border border-cyan-500/30 bg-gradient-to-br from-cyan-500/20 to-violet-500/10">
                <span className="text-lg font-bold tracking-tighter text-cyan-200">W</span>
              </div>
              <div>
                <p className="text-[10px] font-mono uppercase tracking-[0.2em] text-cyan-400/70">Weissman</p>
                <h1 className="text-2xl sm:text-3xl font-bold tracking-tight text-white">{t('status.title')}</h1>
              </div>
            </div>
            <LanguageSwitcher />
          </div>
          <p className="text-sm text-[var(--text-tertiary)] leading-relaxed max-w-2xl">{t('status.subtitle')}</p>
          <EvidenceNotice className="mt-4">{t('status.evidence_notice')}</EvidenceNotice>
        </header>

        <section className="rounded-2xl border border-[var(--border-default)] bg-[var(--bg-2)] backdrop-blur-md p-6 mb-8">
          <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
            <div className="flex items-center gap-4">
              <div className={`flex h-12 w-12 items-center justify-center rounded-full border ${overallMeta.badge}`}>
                <OverallIcon className={`h-6 w-6 ${overallMeta.iconClass}`} />
              </div>
              <div>
                <h2 className="text-lg sm:text-xl font-semibold text-white">
                  {state.loading
                    ? t('status.checking')
                    : overall === 'operational'
                    ? t('status.all_systems_operational')
                    : overall === 'outage'
                    ? t('status.major_outage')
                    : t('status.service_degraded')}
                </h2>
                {state.health?.uptime_secs != null && (
                  <p className="text-xs font-mono text-[var(--text-muted)] mt-1">
                    {t('status.platform_uptime')}: {fmtUptime(state.health.uptime_secs, t)}
                  </p>
                )}
              </div>
            </div>
            <div className="flex items-center gap-3">
              {state.ts && (
                <span className="text-[11px] font-mono text-[var(--text-muted)] flex items-center gap-1.5">
                  <Clock className="h-3.5 w-3.5" />
                  {t('status.last_checked')} {fmtChecked(state.ts, i18n.language)}
                </span>
              )}
              <ShellScanActions
                onRefresh={probe}
                onExport={() => exportStatusCsv(state, t)}
                refreshLoading={state.loading}
              />
            </div>
          </div>

          {hasSafeMode && (
            <div className="mt-4 flex items-start gap-3 rounded-xl border border-amber-500/25 bg-amber-500/10 px-4 py-3">
              <AlertTriangle className="h-4 w-4 text-amber-400 shrink-0 mt-0.5" />
              <p className="text-xs text-amber-100/90 leading-relaxed">{t('status.safe_mode_notice')}</p>
            </div>
          )}
        </section>

        <section className="mb-8">
          <WeissmanListToolbar
            className="mb-4"
            searchQuery={serviceSearch}
            onSearchChange={setServiceSearch}
            searchPlaceholder={t('status.search_components')}
            resultCount={filteredServices.length}
            totalCount={services.length}
          />
          <h3 className="text-[11px] font-mono uppercase tracking-[0.18em] text-[var(--text-muted)] mb-4">
            {t('status.components')}
          </h3>
          <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
            {filteredServices.map((svc) => {
              const meta = serviceMeta[svc.id]
              return (
                <ServiceCard
                  key={svc.id}
                  icon={svc.icon}
                  name={t(meta.nameKey)}
                  description={t(meta.descKey)}
                  level={svc.level}
                  detail={svc.detail}
                  detailLink={svc.detailLink}
                  checkedAt={svc.checkedAt}
                  t={t}
                  locale={i18n.language}
                />
              )
            })}
          </div>
        </section>

        {failedProbes.length > 0 && (
          <section className="rounded-2xl border border-rose-500/25 bg-rose-500/10 backdrop-blur-md p-6 mb-8">
            <h3 className="text-[11px] font-mono uppercase tracking-[0.18em] text-rose-200/80 mb-4">
              {t('status.failed_probes_heading')}
            </h3>
            <ul className="space-y-3">
              {failedProbes.map((probe) => (
                <li
                  key={`${probe.engine_id}-${probe.checked_at || probe.message}`}
                  className="flex flex-col sm:flex-row sm:items-center justify-between gap-2 py-3 border-b border-rose-500/15 last:border-0"
                >
                  <div className="min-w-0">
                    <p className="text-sm text-[var(--text-primary)] font-medium font-mono">{probe.engine_id}</p>
                    <p className="text-xs text-[var(--text-tertiary)] mt-0.5">{probe.message || t('status.health_probe_failed')}</p>
                  </div>
                  {probe.checked_at && (
                    <span className="text-[10px] font-mono text-[var(--text-muted)] shrink-0">
                      {fmtChecked(probe.checked_at, i18n.language)}
                    </span>
                  )}
                </li>
              ))}
            </ul>
          </section>
        )}

        {visibleIncidents.length > 0 && (
          <section className="rounded-2xl border border-[var(--border-default)] bg-[var(--bg-2)] backdrop-blur-md p-6 mb-8">
            <h3 className="text-[11px] font-mono uppercase tracking-[0.18em] text-[var(--text-muted)] mb-4">
              {t('status.incident_history')}
            </h3>
            <ul className="space-y-3">
                {visibleIncidents.map((inc) => {
                  const level = STATUS[inc.level] || STATUS.degraded
                  const name = t(serviceMeta[inc.serviceId]?.nameKey || 'status.components')
                  return (
                    <li
                      key={inc.id}
                      className="flex flex-col sm:flex-row sm:items-center justify-between gap-2 py-3 border-b border-[var(--border-subtle)] last:border-0"
                    >
                      <div className="flex items-start gap-3 min-w-0">
                        <StatusIndicator level={inc.level} />
                        <div>
                          <p className="text-sm text-[var(--text-primary)] font-medium">{name}</p>
                          <p className="text-xs font-mono text-[var(--text-muted)] mt-0.5">{inc.detail || '—'}</p>
                        </div>
                      </div>
                      <div className="text-[10px] font-mono text-[var(--text-muted)] sm:text-right shrink-0">
                        <div>{fmtChecked(inc.startedAt, i18n.language)}</div>
                        {inc.resolvedAt ? (
                          <div className="text-emerald-400/70">{t('status.resolved_at', { time: fmtChecked(inc.resolvedAt, i18n.language) })}</div>
                        ) : (
                          <div className={level.iconClass}>{t('status.ongoing')}</div>
                        )}
                      </div>
                    </li>
                  )
                })}
            </ul>
          </section>
        )}

        <footer className="rounded-2xl border border-[var(--border-default)] bg-[var(--table-surface)] backdrop-blur-md p-5 text-[12px] text-[var(--text-muted)] leading-relaxed">
          <p>{t('status.lightweight_notice')}</p>
          {state.health?.active_engines?.length > 0 && (
            <p className="mt-2 font-mono text-[11px] text-[var(--text-disabled)]">
              {t('status.active_engines', { count: state.health.active_engines.length })}
            </p>
          )}
        </footer>
      </div>
    </div>
  )
}
