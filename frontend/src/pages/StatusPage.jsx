import React, { useCallback, useEffect, useRef, useState } from 'react'
import { useTranslation } from 'react-i18next'
import {
  Activity,
  CheckCircle2,
  AlertTriangle,
  XCircle,
  RefreshCw,
  Clock,
  Database,
  Server,
  Cpu,
  Radio,
} from 'lucide-react'
import { apiFetch, apiUrl } from '../lib/apiBase'
import LanguageSwitcher from '../components/LanguageSwitcher'

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
    iconClass: 'text-white/40',
    badge: 'bg-white/5 text-white/50 border-white/10',
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

function ServiceCard({ icon: Icon, name, description, level, detail, checkedAt, t, locale }) {
  const meta = STATUS[level] || STATUS.unknown
  const StatusIcon = meta.icon
  return (
    <article className="rounded-2xl border border-white/10 bg-black/35 backdrop-blur-md p-5 hover:border-white/15 transition-colors">
      <div className="flex items-start justify-between gap-3 mb-4">
        <div className="flex items-center gap-3 min-w-0">
          <div className="flex h-10 w-10 shrink-0 items-center justify-center rounded-xl border border-white/10 bg-white/5">
            <Icon className="h-5 w-5 text-cyan-400/90" />
          </div>
          <div className="min-w-0">
            <h3 className="text-sm font-semibold text-white/95 truncate">{name}</h3>
            <p className="text-xs text-white/45 mt-0.5 line-clamp-2">{description}</p>
          </div>
        </div>
        <div className={`inline-flex items-center gap-1.5 shrink-0 px-2.5 py-1 rounded-full border text-[10px] font-mono uppercase tracking-wide ${meta.badge}`}>
          <StatusIndicator level={level} />
          {t(meta.labelKey)}
        </div>
      </div>
      <div className="flex items-end justify-between gap-3 pt-3 border-t border-white/5">
        <div className="flex items-center gap-2 min-w-0">
          <StatusIcon className={`h-4 w-4 shrink-0 ${meta.iconClass}`} />
          <span className="text-xs font-mono text-white/70 truncate">{detail || '—'}</span>
        </div>
        {checkedAt && (
          <span className="text-[10px] font-mono text-white/30 whitespace-nowrap flex items-center gap-1">
            <Clock className="h-3 w-3" />
            {fmtChecked(checkedAt, locale)}
          </span>
        )}
      </div>
    </article>
  )
}

function deriveServices(state) {
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
        ? `HTTP ${state.api.status} · ${state.api.latency_ms} ms`
        : state.api.error || `HTTP ${state.api.status || 0}`
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
      ? 'PostgreSQL reachable'
      : state.health?.postgres_ok === false
      ? 'PostgreSQL unreachable'
      : state.api?.ok
      ? 'Health payload missing postgres_ok'
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
        ? `${state.health.active_tenant_cycles ?? 0} active tenant cycles`
        : state.health.scanning_enabled
        ? 'Scanning enabled'
        : 'Scanning paused'
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
      ? `${state.engines.production_count} production · ${state.engines.catalog_count} catalog`
      : state.engines?.error || (state.engines?.status ? `HTTP ${state.engines.status}` : null),
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
        ? `${state.agents.online}/${state.agents.total} online`
        : state.agents.detail
      : state.agents?.error || (state.agents?.status ? `HTTP ${state.agents.status}` : null),
    checkedAt: ts,
  })

  return services
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
      const r = await apiFetch('/api/agents/status')
      if (r.ok) {
        const d = await r.json()
        result.agents = {
          ok: true,
          total: d.agents?.length || 0,
          online: d.online_count || 0,
        }
      } else if (r.status === 401) {
        result.agents = { ok: true, online_visible: false, detail: t('status.agents_auth_required') }
      } else {
        result.agents = { ok: false, status: r.status }
      }
    } catch (e) {
      result.agents = { ok: false, error: e.message }
    }

    setState(result)
    const services = deriveServices({ ...result, loading: false })
    recordIncidents(services, ts)
  }, [recordIncidents, t])

  useEffect(() => {
    probe()
    const interval = setInterval(probe, 30_000)
    return () => clearInterval(interval)
  }, [probe])

  const services = deriveServices(state)
  const overall = overallLevel(services, state)
  const overallMeta = STATUS[overall] || STATUS.unknown
  const OverallIcon = overallMeta.icon

  const serviceMeta = {
    api: { nameKey: 'status.api_auth', descKey: 'status.api_auth_desc' },
    database: { nameKey: 'status.database', descKey: 'status.database_desc' },
    scanning: { nameKey: 'status.scan_orchestrator', descKey: 'status.scan_orchestrator_desc' },
    engines: { nameKey: 'status.engine_registry', descKey: 'status.engine_registry_desc' },
    agents: { nameKey: 'status.endpoint_agents', descKey: 'status.endpoint_agents_desc' },
  }

  const visibleIncidents = incidents.filter((i) => i.level !== 'operational')
  const hasSafeMode = state.health?.global_safe_mode === true

  return (
    <div
      className="min-h-[100dvh] text-slate-100"
      style={{ background: 'radial-gradient(ellipse 100% 70% at 50% 0%, #0f172a 0%, #020617 55%, #000 100%)' }}
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
          <p className="text-sm text-white/55 leading-relaxed max-w-2xl">{t('status.subtitle')}</p>
        </header>

        <section className="rounded-2xl border border-white/10 bg-black/40 backdrop-blur-md p-6 mb-8">
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
                  <p className="text-xs font-mono text-white/40 mt-1">
                    {t('status.platform_uptime')}: {fmtUptime(state.health.uptime_secs, t)}
                  </p>
                )}
              </div>
            </div>
            <div className="flex items-center gap-3">
              {state.ts && (
                <span className="text-[11px] font-mono text-white/35 flex items-center gap-1.5">
                  <Clock className="h-3.5 w-3.5" />
                  {t('status.last_checked')} {fmtChecked(state.ts, i18n.language)}
                </span>
              )}
              <button
                type="button"
                onClick={probe}
                className="inline-flex items-center gap-2 px-3 py-2 rounded-xl text-xs font-medium border border-white/10 bg-white/5 text-white/60 hover:text-white hover:border-white/25 transition-colors"
              >
                <RefreshCw className={`h-3.5 w-3.5 ${state.loading ? 'animate-spin' : ''}`} />
                {t('common.refresh')}
              </button>
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
          <h3 className="text-[11px] font-mono uppercase tracking-[0.18em] text-white/40 mb-4">
            {t('status.components')}
          </h3>
          <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
            {services.map((svc) => {
              const meta = serviceMeta[svc.id]
              return (
                <ServiceCard
                  key={svc.id}
                  icon={svc.icon}
                  name={t(meta.nameKey)}
                  description={t(meta.descKey)}
                  level={svc.level}
                  detail={svc.detail}
                  checkedAt={svc.checkedAt}
                  t={t}
                  locale={i18n.language}
                />
              )
            })}
          </div>
        </section>

        {visibleIncidents.length > 0 && (
          <section className="rounded-2xl border border-white/10 bg-black/40 backdrop-blur-md p-6 mb-8">
            <h3 className="text-[11px] font-mono uppercase tracking-[0.18em] text-white/40 mb-4">
              {t('status.incident_history')}
            </h3>
            <ul className="space-y-3">
                {visibleIncidents.map((inc) => {
                  const level = STATUS[inc.level] || STATUS.degraded
                  const name = t(serviceMeta[inc.serviceId]?.nameKey || 'status.components')
                  return (
                    <li
                      key={inc.id}
                      className="flex flex-col sm:flex-row sm:items-center justify-between gap-2 py-3 border-b border-white/5 last:border-0"
                    >
                      <div className="flex items-start gap-3 min-w-0">
                        <StatusIndicator level={inc.level} />
                        <div>
                          <p className="text-sm text-white/85 font-medium">{name}</p>
                          <p className="text-xs font-mono text-white/45 mt-0.5">{inc.detail || '—'}</p>
                        </div>
                      </div>
                      <div className="text-[10px] font-mono text-white/35 sm:text-right shrink-0">
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

        <footer className="rounded-2xl border border-white/10 bg-black/30 backdrop-blur-md p-5 text-[12px] text-white/45 leading-relaxed">
          <p>{t('status.lightweight_notice')}</p>
          {state.health?.active_engines?.length > 0 && (
            <p className="mt-2 font-mono text-[11px] text-white/30">
              {t('status.active_engines', { count: state.health.active_engines.length })}
            </p>
          )}
        </footer>
      </div>
    </div>
  )
}
