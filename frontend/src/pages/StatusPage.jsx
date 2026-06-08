import React, { useEffect, useState } from 'react'
import { useTranslation } from 'react-i18next'
import { apiFetch, apiUrl } from '../lib/apiBase'
import LanguageSwitcher from '../components/LanguageSwitcher'

function StatusDot({ ok }) {
  return (
    <span
      className={`inline-block w-3 h-3 rounded-full ${ok ? 'bg-emerald-400' : 'bg-rose-500'} shadow`}
      style={{ boxShadow: ok ? '0 0 12px rgba(52,211,153,.6)' : '0 0 12px rgba(244,63,94,.6)' }}
    />
  )
}

function Row({ label, ok, detail }) {
  return (
    <div className="flex items-center justify-between gap-3 py-3 border-b border-white/5">
      <div className="flex items-center gap-3">
        <StatusDot ok={ok} />
        <span className="text-sm font-mono text-white/85">{label}</span>
      </div>
      <span className={`text-[11px] font-mono ${ok ? 'text-emerald-300' : 'text-rose-300'}`}>
        {detail}
      </span>
    </div>
  )
}

/**
 * Public status page — no auth required. Pings the API health endpoint, the production engine
 * registry, and the agent status. Used by customers + uptime monitors.
 */
export default function StatusPage() {
  const { t } = useTranslation()
  const [state, setState] = useState({
    loading: true,
    api: null,
    engines: null,
    agents: null,
    error: null,
    ts: null,
  })

  useEffect(() => {
    let cancelled = false
    async function probe() {
      const t0 = performance.now()
      const result = { loading: false, api: null, engines: null, agents: null, error: null, ts: new Date().toISOString() }
      try {
        const r = await fetch(apiUrl('/api/health'), { credentials: 'omit' })
        result.api = {
          ok: r.ok,
          status: r.status,
          latency_ms: Math.round(performance.now() - t0),
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
          result.agents = { ok: true, online_visible: false, detail: 'auth required (operator+)' }
        } else {
          result.agents = { ok: false, status: r.status }
        }
      } catch (e) {
        result.agents = { ok: false, error: e.message }
      }
      if (!cancelled) setState(result)
    }
    probe()
    const t = setInterval(probe, 30_000)
    return () => {
      cancelled = true
      clearInterval(t)
    }
  }, [])

  const overall = state.api?.ok && state.engines?.ok

  return (
    <div
      className="min-h-[100dvh] text-slate-100 p-6"
      style={{ background: 'radial-gradient(ellipse 100% 70% at 50% 0%, #0f172a 0%, #020617 60%, #000 100%)' }}
    >
      <header className="max-w-3xl mx-auto mb-8">
        <div className="flex justify-between items-start gap-3 mb-4">
          <h1 className="text-3xl font-bold tracking-tight">{t('status.title')}</h1>
          <LanguageSwitcher />
        </div>
        <p className="text-sm text-white/55 mt-2">
          {t('status.subtitle')}
        </p>
      </header>

      <section className="max-w-3xl mx-auto rounded-2xl bg-black/40 border border-white/10 backdrop-blur-md p-6 mb-6">
        <div className="flex items-center gap-4">
          <StatusDot ok={!!overall} />
          <h2 className="text-lg font-semibold">
            {state.loading
              ? t('status.checking')
              : overall
              ? t('status.all_systems_operational')
              : t('status.service_degraded')}
          </h2>
        </div>
        {state.ts && (
          <p className="text-[11px] font-mono text-white/35 mt-2">
            {t('status.last_checked')} {new Date(state.ts).toLocaleTimeString()}
          </p>
        )}
      </section>

      <section className="max-w-3xl mx-auto rounded-2xl bg-black/40 border border-white/10 backdrop-blur-md p-6 mb-6">
        <h3 className="text-xs font-mono uppercase tracking-widest text-white/45 mb-3">{t('status.components')}</h3>
        <Row
          label={t('status.api_auth')}
          ok={!!state.api?.ok}
          detail={
            state.api
              ? `HTTP ${state.api.status} · ${state.api.latency_ms} ms`
              : '—'
          }
        />
        <Row
          label={t('status.engine_registry')}
          ok={!!state.engines?.ok}
          detail={
            state.engines?.ok
              ? `${state.engines.production_count} live / ${state.engines.catalog_count} catalog`
              : '—'
          }
        />
        <Row
          label={t('status.endpoint_agents')}
          ok={!!state.agents?.ok}
          detail={
            state.agents?.ok && state.agents.online !== undefined
              ? `${state.agents.online}/${state.agents.total} online`
              : state.agents?.detail || '—'
          }
        />
      </section>

      <section className="max-w-3xl mx-auto rounded-2xl bg-black/40 border border-white/10 backdrop-blur-md p-6 text-[12px] font-mono text-white/55">
        <p>{t('status.lightweight_notice')}</p>
      </section>
    </div>
  )
}
