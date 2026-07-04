import { useCallback, useEffect, useMemo, useState } from 'react'
import { useTranslation } from 'react-i18next'
import {
  Activity,
  AlertTriangle,
  Box,
  Cpu,
  Layers,
  ListTodo,
  RefreshCw,
  Search,
  Server,
  Shield,
  Zap,
} from 'lucide-react'
import CeoProtectedRoute from '../components/ceo/CeoProtectedRoute'
import { apiFetch } from '../lib/apiBase'

const POLL_MS = 2000
const SECTIONS = ['overview', 'engines', 'modules', 'jobs', 'controls']

function lifecycleTone(lc) {
  if (lc === 'running') return '#22d3ee'
  if (lc === 'stuck') return '#f97316'
  if (lc === 'failed') return '#ef4444'
  return '#64748b'
}

function moduleStatusTone(s) {
  if (s === 'healthy') return '#34d399'
  if (s === 'degraded') return '#fbbf24'
  if (s === 'down') return '#ef4444'
  return '#94a3b8'
}

function formatMs(ms) {
  if (ms == null || ms === 0) return '—'
  if (ms < 1000) return `${ms}ms`
  const s = Math.round(ms / 1000)
  if (s < 60) return `${s}s`
  return `${Math.floor(s / 60)}m ${s % 60}s`
}

function collectClientBootModules() {
  const resources = performance.getEntriesByType('resource') || []
  const scripts = resources
    .filter((r) => r.initiatorType === 'script' || /\.js(\?|$)/.test(r.name))
    .slice(-40)
    .map((r) => ({
      name: r.name.split('/').pop()?.split('?')[0] || r.name,
      duration_ms: Math.round(r.duration),
      loaded: r.responseEnd > 0,
      phase: r.responseEnd > 0 ? 'loaded' : 'pending',
    }))

  return {
    document_ready: document.readyState,
    navigation_ms: Math.round(performance.timing?.domContentLoadedEventEnd - performance.timing?.navigationStart || 0),
    script_chunks: scripts,
    sw_controller: Boolean(navigator.serviceWorker?.controller),
    locale: document.documentElement.lang || 'unknown',
  }
}

function SummaryCard({ label, value, tone, icon: Icon }) {
  return (
    <div className="rounded-xl border border-white/10 bg-black/50 p-4 backdrop-blur-md">
      <div className="mb-2 flex items-center justify-between">
        <span className="text-xs uppercase tracking-wider text-slate-500">{label}</span>
        {Icon ? <Icon className="h-4 w-4 text-slate-500" /> : null}
      </div>
      <div className="text-2xl font-bold tabular-nums" style={{ color: tone || '#f8fafc' }}>
        {value}
      </div>
    </div>
  )
}

function SupremeNerveCenterInner() {
  const { t } = useTranslation()
  const [section, setSection] = useState('overview')
  const [snap, setSnap] = useState(null)
  const [error, setError] = useState(null)
  const [loading, setLoading] = useState(true)
  const [query, setQuery] = useState('')
  const [lifecycleFilter, setLifecycleFilter] = useState('all')
  const [clientBoot, setClientBoot] = useState(null)
  const [lastRefresh, setLastRefresh] = useState(null)

  const load = useCallback(async () => {
    try {
      const r = await apiFetch('/api/ceo/supreme/nerve-center')
      if (!r.ok) {
        const body = await r.json().catch(() => ({}))
        throw new Error(body.detail || `HTTP ${r.status}`)
      }
      setSnap(await r.json())
      setError(null)
      setLastRefresh(new Date())
    } catch (e) {
      setError(e?.message || 'Failed to load nerve center')
    } finally {
      setLoading(false)
    }
  }, [])

  useEffect(() => {
    setClientBoot(collectClientBootModules())
    load()
    const id = setInterval(load, POLL_MS)
    return () => clearInterval(id)
  }, [load])

  const engines = snap?.engines || []
  const modules = snap?.system_modules || []
  const jobs = snap?.live_jobs || []
  const summary = snap?.summary || {}
  const controls = snap?.control_parameters || {}

  const filteredEngines = useMemo(() => {
    const q = query.trim().toLowerCase()
    return engines.filter((e) => {
      if (lifecycleFilter !== 'all' && e.lifecycle !== lifecycleFilter) return false
      if (!q) return true
      return (
        String(e.engine_id).toLowerCase().includes(q) ||
        String(e.phase || '').toLowerCase().includes(q) ||
        String(e.target || '').toLowerCase().includes(q)
      )
    })
  }, [engines, query, lifecycleFilter])

  const stuckEngines = useMemo(
    () => engines.filter((e) => e.lifecycle === 'stuck'),
    [engines],
  )

  const sectionLabel = (id) => t(`supremeNerveCenter.sections.${id}`, id)

  return (
    <div className="flex min-h-screen bg-[#020617] text-slate-100">
      <aside className="flex w-56 shrink-0 flex-col border-r border-white/10 bg-[#030712]/90">
        <div className="border-b border-white/10 p-4">
          <div className="flex items-center gap-2 text-emerald-400">
            <Zap className="h-5 w-5" />
            <span className="text-sm font-semibold tracking-wide">
              {t('supremeNerveCenter.title')}
            </span>
          </div>
          <p className="mt-1 text-[10px] font-mono uppercase tracking-widest text-slate-500">
            {t('supremeNerveCenter.ceoOnly')}
          </p>
        </div>
        <nav className="flex-1 space-y-1 p-2">
          {SECTIONS.map((id) => (
            <button
              key={id}
              type="button"
              onClick={() => setSection(id)}
              className={`w-full rounded-lg px-3 py-2 text-left text-sm transition ${
                section === id
                  ? 'bg-emerald-500/15 text-emerald-300'
                  : 'text-slate-400 hover:bg-white/5 hover:text-slate-200'
              }`}
            >
              {sectionLabel(id)}
            </button>
          ))}
        </nav>
        <div className="border-t border-white/10 p-3 text-[10px] font-mono text-slate-600">
          {lastRefresh ? lastRefresh.toLocaleTimeString() : '—'}
          <br />
          {t('supremeNerveCenter.pollInterval', { sec: POLL_MS / 1000 })}
        </div>
      </aside>

      <main className="flex-1 overflow-auto p-6">
        <header className="mb-6 flex flex-wrap items-center justify-between gap-4">
          <div>
            <h1 className="text-xl font-semibold text-white">{sectionLabel(section)}</h1>
            <p className="text-xs text-slate-500">{t('supremeNerveCenter.evidence_notice')}</p>
          </div>
          <button
            type="button"
            onClick={load}
            className="inline-flex items-center gap-2 rounded-lg border border-white/10 px-3 py-1.5 text-xs font-mono text-slate-300 hover:bg-white/5"
          >
            <RefreshCw className={`h-3.5 w-3.5 ${loading ? 'animate-spin' : ''}`} />
            {t('supremeNerveCenter.refresh')}
          </button>
        </header>

        {error ? (
          <div className="mb-4 rounded-lg border border-red-500/30 bg-red-950/30 px-4 py-3 text-sm text-red-300">
            {error}
          </div>
        ) : null}

        {stuckEngines.length > 0 ? (
          <div className="mb-4 flex items-start gap-3 rounded-lg border border-orange-500/40 bg-orange-950/20 px-4 py-3">
            <AlertTriangle className="mt-0.5 h-5 w-5 shrink-0 text-orange-400" />
            <div>
              <p className="text-sm font-medium text-orange-200">
                {t('supremeNerveCenter.stuckAlert', { count: stuckEngines.length })}
              </p>
              <p className="mt-1 text-xs text-orange-200/70">
                {stuckEngines
                  .slice(0, 5)
                  .map((e) => e.engine_id)
                  .join(', ')}
                {stuckEngines.length > 5 ? '…' : ''}
              </p>
            </div>
          </div>
        ) : null}

        {section === 'overview' && (
          <div className="space-y-6">
            <div className="grid grid-cols-2 gap-4 md:grid-cols-4 xl:grid-cols-6">
              <SummaryCard
                label={t('supremeNerveCenter.metrics.enginesTotal')}
                value={summary.engines_total ?? '—'}
                icon={Cpu}
              />
              <SummaryCard
                label={t('supremeNerveCenter.metrics.running')}
                value={summary.engines_running ?? 0}
                tone="#22d3ee"
                icon={Activity}
              />
              <SummaryCard
                label={t('supremeNerveCenter.metrics.stuck')}
                value={summary.engines_stuck ?? 0}
                tone="#f97316"
                icon={AlertTriangle}
              />
              <SummaryCard
                label={t('supremeNerveCenter.metrics.liveJobs')}
                value={summary.live_jobs ?? 0}
                icon={ListTodo}
              />
              <SummaryCard
                label={t('supremeNerveCenter.metrics.inFlight')}
                value={summary.in_flight_runs ?? 0}
                icon={Zap}
              />
              <SummaryCard
                label={t('supremeNerveCenter.metrics.modules')}
                value={modules.length}
                icon={Layers}
              />
            </div>

            <div className="grid gap-4 lg:grid-cols-2">
              <div className="rounded-xl border border-white/10 bg-black/40 p-4">
                <h2 className="mb-3 text-sm font-medium text-slate-300">
                  {t('supremeNerveCenter.activeRuns')}
                </h2>
                <div className="max-h-64 space-y-2 overflow-auto">
                  {engines
                    .filter((e) => e.lifecycle === 'running' || e.lifecycle === 'stuck')
                    .slice(0, 20)
                    .map((e) => (
                      <div
                        key={`${e.engine_id}-${e.job_id}`}
                        className="rounded border border-white/5 bg-white/[0.02] px-3 py-2 text-xs"
                      >
                        <div className="flex justify-between gap-2">
                          <span className="font-mono text-cyan-300">{e.engine_id}</span>
                          <span style={{ color: lifecycleTone(e.lifecycle) }}>{e.lifecycle}</span>
                        </div>
                        <div className="mt-1 text-slate-500">
                          {e.phase}
                          {e.phase_detail ? ` · ${e.phase_detail}` : ''}
                        </div>
                        <div className="mt-1 font-mono text-[10px] text-slate-600">
                          {formatMs(e.elapsed_ms)} · {e.target || '—'}
                        </div>
                      </div>
                    ))}
                  {!engines.some((e) => e.lifecycle === 'running' || e.lifecycle === 'stuck') ? (
                    <p className="text-xs text-slate-600">{t('supremeNerveCenter.noActiveRuns')}</p>
                  ) : null}
                </div>
              </div>

              <div className="rounded-xl border border-white/10 bg-black/40 p-4">
                <h2 className="mb-3 text-sm font-medium text-slate-300">
                  {t('supremeNerveCenter.clientBoot')}
                </h2>
                {clientBoot ? (
                  <dl className="space-y-2 text-xs">
                    <div className="flex justify-between">
                      <dt className="text-slate-500">{t('supremeNerveCenter.documentReady')}</dt>
                      <dd className="font-mono">{clientBoot.document_ready}</dd>
                    </div>
                    <div className="flex justify-between">
                      <dt className="text-slate-500">{t('supremeNerveCenter.domMs')}</dt>
                      <dd className="font-mono">{clientBoot.navigation_ms}ms</dd>
                    </div>
                    <div className="flex justify-between">
                      <dt className="text-slate-500">SW</dt>
                      <dd className="font-mono">{clientBoot.sw_controller ? 'active' : 'none'}</dd>
                    </div>
                    <div className="flex justify-between">
                      <dt className="text-slate-500">{t('supremeNerveCenter.chunksLoaded')}</dt>
                      <dd className="font-mono">
                        {clientBoot.script_chunks.filter((c) => c.loaded).length}/
                        {clientBoot.script_chunks.length}
                      </dd>
                    </div>
                  </dl>
                ) : null}
              </div>
            </div>
          </div>
        )}

        {section === 'engines' && (
          <div className="space-y-4">
            <div className="flex flex-wrap gap-3">
              <div className="relative min-w-[200px] flex-1">
                <Search className="absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-slate-500" />
                <input
                  type="search"
                  value={query}
                  onChange={(e) => setQuery(e.target.value)}
                  placeholder={t('supremeNerveCenter.searchEngines')}
                  className="w-full rounded-lg border border-white/10 bg-black/40 py-2 pl-9 pr-3 text-sm text-slate-200 placeholder:text-slate-600"
                />
              </div>
              <select
                value={lifecycleFilter}
                onChange={(e) => setLifecycleFilter(e.target.value)}
                className="rounded-lg border border-white/10 bg-black/40 px-3 py-2 text-sm text-slate-300"
              >
                <option value="all">{t('supremeNerveCenter.filterAll')}</option>
                <option value="running">{t('supremeNerveCenter.filterRunning')}</option>
                <option value="stuck">{t('supremeNerveCenter.filterStuck')}</option>
                <option value="idle">{t('supremeNerveCenter.filterIdle')}</option>
                <option value="failed">{t('supremeNerveCenter.filterFailed')}</option>
              </select>
            </div>

            <div className="overflow-x-auto rounded-xl border border-white/10">
              <table className="w-full min-w-[900px] text-left text-xs">
                <thead className="bg-white/[0.03] text-[10px] uppercase tracking-wider text-slate-500">
                  <tr>
                    <th className="px-3 py-2">{t('supremeNerveCenter.colEngine')}</th>
                    <th className="px-3 py-2">{t('supremeNerveCenter.colLifecycle')}</th>
                    <th className="px-3 py-2">{t('supremeNerveCenter.colPhase')}</th>
                    <th className="px-3 py-2">{t('supremeNerveCenter.colElapsed')}</th>
                    <th className="px-3 py-2">{t('supremeNerveCenter.colTarget')}</th>
                    <th className="px-3 py-2">{t('supremeNerveCenter.colLastStatus')}</th>
                    <th className="px-3 py-2">{t('supremeNerveCenter.colRuns')}</th>
                  </tr>
                </thead>
                <tbody>
                  {filteredEngines.map((e) => (
                    <tr key={e.engine_id} className="border-t border-white/5 hover:bg-white/[0.02]">
                      <td className="px-3 py-2 font-mono text-cyan-300/90">{e.engine_id}</td>
                      <td className="px-3 py-2">
                        <span style={{ color: lifecycleTone(e.lifecycle) }}>{e.lifecycle}</span>
                        {e.stuck_reason ? (
                          <div className="mt-0.5 text-[10px] text-orange-400">{e.stuck_reason}</div>
                        ) : null}
                      </td>
                      <td className="px-3 py-2 text-slate-400">
                        {e.phase || '—'}
                        {e.phase_detail ? (
                          <div className="text-[10px] text-slate-600">{e.phase_detail}</div>
                        ) : null}
                      </td>
                      <td className="px-3 py-2 font-mono tabular-nums">{formatMs(e.elapsed_ms)}</td>
                      <td className="max-w-[140px] truncate px-3 py-2 font-mono text-slate-500">
                        {e.target || '—'}
                      </td>
                      <td className="px-3 py-2">{e.last_status}</td>
                      <td className="px-3 py-2 tabular-nums">
                        {e.total_runs}
                        {e.failed_runs > 0 ? (
                          <span className="ml-1 text-red-400">({e.failed_runs} fail)</span>
                        ) : null}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
              <p className="border-t border-white/5 px-3 py-2 text-[10px] text-slate-600">
                {t('supremeNerveCenter.engineCount', {
                  shown: filteredEngines.length,
                  total: engines.length,
                })}
              </p>
            </div>
          </div>
        )}

        {section === 'modules' && (
          <div className="grid gap-4 md:grid-cols-2 xl:grid-cols-3">
            {modules.map((m) => (
              <div
                key={m.id}
                className="rounded-xl border border-white/10 bg-black/40 p-4 backdrop-blur-sm"
              >
                <div className="mb-2 flex items-start justify-between gap-2">
                  <div>
                    <h3 className="text-sm font-medium text-slate-200">{m.label}</h3>
                    <span className="text-[10px] font-mono uppercase text-slate-600">{m.category}</span>
                  </div>
                  <span
                    className="rounded px-2 py-0.5 text-[10px] font-mono uppercase"
                    style={{
                      color: moduleStatusTone(m.status),
                      border: `1px solid ${moduleStatusTone(m.status)}40`,
                    }}
                  >
                    {m.status}
                  </span>
                </div>
                <p className="mb-3 text-xs leading-relaxed text-slate-500">{m.description}</p>
                <dl className="space-y-1 text-[11px]">
                  <div className="flex justify-between">
                    <dt className="text-slate-600">{t('supremeNerveCenter.moduleLoaded')}</dt>
                    <dd>{m.loaded ? t('supremeNerveCenter.yes') : t('supremeNerveCenter.no')}</dd>
                  </div>
                  <div className="flex justify-between">
                    <dt className="text-slate-600">{t('supremeNerveCenter.modulePhase')}</dt>
                    <dd className="font-mono">{m.phase}</dd>
                  </div>
                </dl>
                {m.metrics && Object.keys(m.metrics).length > 0 ? (
                  <pre className="mt-3 max-h-24 overflow-auto rounded bg-black/50 p-2 text-[10px] text-slate-500">
                    {JSON.stringify(m.metrics, null, 2)}
                  </pre>
                ) : null}
              </div>
            ))}

            {clientBoot?.script_chunks?.length ? (
              <div className="rounded-xl border border-dashed border-white/10 bg-black/20 p-4 md:col-span-2 xl:col-span-3">
                <h3 className="mb-3 flex items-center gap-2 text-sm text-slate-300">
                  <Box className="h-4 w-4" />
                  {t('supremeNerveCenter.frontendChunks')}
                </h3>
                <div className="grid max-h-48 gap-1 overflow-auto font-mono text-[10px] md:grid-cols-2 lg:grid-cols-3">
                  {clientBoot.script_chunks.map((c) => (
                    <div
                      key={c.name}
                      className={`rounded px-2 py-1 ${c.loaded ? 'text-emerald-500/80' : 'text-amber-500/80'}`}
                    >
                      {c.name} · {c.duration_ms}ms · {c.phase}
                    </div>
                  ))}
                </div>
              </div>
            ) : null}
          </div>
        )}

        {section === 'jobs' && (
          <div className="overflow-x-auto rounded-xl border border-white/10">
            <table className="w-full min-w-[800px] text-left text-xs">
              <thead className="bg-white/[0.03] text-[10px] uppercase tracking-wider text-slate-500">
                <tr>
                  <th className="px-3 py-2">ID</th>
                  <th className="px-3 py-2">{t('supremeNerveCenter.colKind')}</th>
                  <th className="px-3 py-2">{t('supremeNerveCenter.colStatus')}</th>
                  <th className="px-3 py-2">{t('supremeNerveCenter.colEngine')}</th>
                  <th className="px-3 py-2">HB stale</th>
                  <th className="px-3 py-2">{t('supremeNerveCenter.colWorker')}</th>
                </tr>
              </thead>
              <tbody>
                {jobs.map((j) => (
                  <tr key={j.id} className="border-t border-white/5">
                    <td className="px-3 py-2 font-mono text-[10px]">{j.id?.slice(0, 8)}…</td>
                    <td className="px-3 py-2">{j.kind}</td>
                    <td className="px-3 py-2">{j.status}</td>
                    <td className="px-3 py-2 font-mono text-cyan-400/80">{j.engine_id || '—'}</td>
                    <td
                      className={`px-3 py-2 tabular-nums ${
                        (j.heartbeat_stale_secs || 0) > 120 ? 'text-orange-400' : ''
                      }`}
                    >
                      {j.heartbeat_stale_secs ?? '—'}s
                    </td>
                    <td className="px-3 py-2 font-mono text-[10px] text-slate-500">
                      {j.worker_id || '—'}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
            {!jobs.length ? (
              <p className="px-4 py-6 text-center text-xs text-slate-600">
                {t('supremeNerveCenter.noJobs')}
              </p>
            ) : null}
          </div>
        )}

        {section === 'controls' && (
          <div className="grid gap-4 md:grid-cols-2">
            <div className="rounded-xl border border-white/10 bg-black/40 p-4">
              <h2 className="mb-3 flex items-center gap-2 text-sm text-slate-300">
                <Shield className="h-4 w-4" />
                {t('supremeNerveCenter.controlParams')}
              </h2>
              <dl className="space-y-2 text-xs">
                {Object.entries(controls).map(([k, v]) => (
                  <div key={k} className="flex justify-between gap-4 border-b border-white/5 py-1.5">
                    <dt className="font-mono text-slate-500">{k}</dt>
                    <dd className="font-mono text-slate-300">{String(v)}</dd>
                  </div>
                ))}
              </dl>
            </div>
            <div className="rounded-xl border border-white/10 bg-black/40 p-4">
              <h2 className="mb-3 flex items-center gap-2 text-sm text-slate-300">
                <Server className="h-4 w-4" />
                {t('supremeNerveCenter.ceoTelemetry')}
              </h2>
              <pre className="max-h-96 overflow-auto text-[10px] text-slate-500">
                {JSON.stringify(snap?.ceo_telemetry || {}, null, 2)}
              </pre>
            </div>
          </div>
        )}
      </main>
    </div>
  )
}

export default function SupremeNerveCenter() {
  return (
    <CeoProtectedRoute>
      <SupremeNerveCenterInner />
    </CeoProtectedRoute>
  )
}
