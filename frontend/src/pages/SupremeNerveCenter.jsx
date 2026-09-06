import { useCallback, useEffect, useMemo, useState } from 'react'
import { useTranslation } from 'react-i18next'
import {
  Activity,
  AlertTriangle,
  Box,
  Cpu,
  Layers,
  ListTodo,
  Search,
  Server,
  Shield,
  Zap,
} from 'lucide-react'
import { createColumnHelper } from '@tanstack/react-table'
import CeoProtectedRoute from '../components/ceo/CeoProtectedRoute'
import EvidenceNotice from '../components/ui/EvidenceNotice'
import ShellScanActions from '../components/engine/ShellScanActions'
import DataTable from '../components/ui/DataTable'
import { apiFetch } from '../utils/apiFetch'
import { useVisiblePolling } from '../hooks/useVisiblePolling'
import Button from '../components/ui/Button'
import { PRODUCTION_ENGINE_COUNT } from '../lib/platformScale'

// 10s cadence: each poll is a ~500-row DB query plus an O(engines × live_runs) scan
// and a several-hundred-KB snapshot, so sub-10s polling is pure waste.
const POLL_MS = 10000
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
    <div className="rounded-xl border border-[var(--border-default)] bg-[var(--bg-3)] p-4 backdrop-blur-md">
      <div className="mb-2 flex items-center justify-between">
        <span className="text-xs uppercase tracking-wider text-[var(--text-muted)]">{label}</span>
        {Icon ? <Icon className="h-4 w-4 text-[var(--text-muted)]" /> : null}
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
  const [searchQuery, setSearchQuery] = useState('')
  const [lifecycleFilter, setLifecycleFilter] = useState('all')
  const [clientBoot, setClientBoot] = useState(null)
  const [lastRefresh, setLastRefresh] = useState(null)

  const load = useCallback(async () => {
    try {
      const d = await apiFetch('/api/ceo/supreme/nerve-center')
      setSnap(d)
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
  }, [load])

  // Refresh on POLL_MS cadence, skipping ticks while the tab is hidden.
  useVisiblePolling(load, POLL_MS)

  // eslint-disable-next-line react-hooks/exhaustive-deps
  const engines = snap?.engines || []
  const modules = snap?.system_modules || []
  const jobs = snap?.live_jobs || []
  const summary = snap?.summary || {}
  const controls = snap?.control_parameters || {}

  const filteredEngines = useMemo(() => {
    const q = searchQuery.trim().toLowerCase()
    return engines.filter((e) => {
      if (lifecycleFilter !== 'all' && e.lifecycle !== lifecycleFilter) return false
      if (!q) return true
      return (
        String(e.engine_id).toLowerCase().includes(q) ||
        String(e.phase || '').toLowerCase().includes(q) ||
        String(e.target || '').toLowerCase().includes(q)
      )
    })
  }, [engines, searchQuery, lifecycleFilter])

  const engineColumns = useMemo(() => {
    const ch = createColumnHelper()
    return [
      ch.accessor('engine_id', {
        id: 'engine',
        header: t('supremeNerveCenter.colEngine'),
        cell: ({ getValue }) => <span className="font-mono text-cyan-300/90">{getValue()}</span>,
      }),
      ch.accessor('lifecycle', {
        id: 'lifecycle',
        header: t('supremeNerveCenter.colLifecycle'),
        cell: ({ row, getValue }) => (
          <span>
            <span style={{ color: lifecycleTone(getValue()) }}>{getValue()}</span>
            {row.original.stuck_reason ? (
              <div className="mt-0.5 text-[10px] text-orange-400">{row.original.stuck_reason}</div>
            ) : null}
          </span>
        ),
      }),
      ch.accessor((e) => e.phase || '—', {
        id: 'phase',
        header: t('supremeNerveCenter.colPhase'),
        cell: ({ row, getValue }) => (
          <span className="text-[var(--text-tertiary)]">
            {getValue()}
            {row.original.phase_detail ? (
              <div className="text-[10px] text-[var(--text-muted)]">{row.original.phase_detail}</div>
            ) : null}
          </span>
        ),
      }),
      ch.accessor((e) => e.elapsed_ms || 0, {
        id: 'elapsed',
        header: t('supremeNerveCenter.colElapsed'),
        size: 110,
        cell: ({ getValue }) => <span className="font-mono tabular-nums">{formatMs(getValue())}</span>,
      }),
      ch.accessor((e) => e.target || '—', {
        id: 'target',
        header: t('supremeNerveCenter.colTarget'),
        cell: ({ getValue }) => (
          <span className="block max-w-[140px] truncate font-mono text-[var(--text-muted)]">{getValue()}</span>
        ),
      }),
      ch.accessor('last_status', {
        id: 'last_status',
        header: t('supremeNerveCenter.colLastStatus'),
        cell: ({ getValue }) => <span>{getValue()}</span>,
      }),
      ch.accessor((e) => e.total_runs || 0, {
        id: 'runs',
        header: t('supremeNerveCenter.colRuns'),
        size: 100,
        cell: ({ row, getValue }) => (
          <span className="tabular-nums">
            {getValue()}
            {row.original.failed_runs > 0 ? (
              <span className="ml-1 text-red-400">({row.original.failed_runs} fail)</span>
            ) : null}
          </span>
        ),
      }),
    ]
  }, [t])

  const jobColumns = useMemo(() => {
    const ch = createColumnHelper()
    return [
      ch.accessor('id', {
        id: 'id',
        header: 'ID',
        size: 110,
        cell: ({ getValue }) => <span className="font-mono text-[10px]">{String(getValue() || '').slice(0, 8)}…</span>,
      }),
      ch.accessor('kind', { id: 'kind', header: t('supremeNerveCenter.colKind'), cell: ({ getValue }) => getValue() }),
      ch.accessor('status', { id: 'status', header: t('supremeNerveCenter.colStatus'), cell: ({ getValue }) => getValue() }),
      ch.accessor((j) => j.engine_id || '—', {
        id: 'engine',
        header: t('supremeNerveCenter.colEngine'),
        cell: ({ getValue }) => <span className="font-mono text-cyan-400/80">{getValue()}</span>,
      }),
      ch.accessor((j) => j.heartbeat_stale_secs ?? -1, {
        id: 'hb',
        header: 'HB stale',
        size: 110,
        cell: ({ row }) => (
          <span className={`tabular-nums ${(row.original.heartbeat_stale_secs || 0) > 120 ? 'text-orange-400' : ''}`}>
            {row.original.heartbeat_stale_secs ?? '—'}s
          </span>
        ),
      }),
      ch.accessor((j) => j.worker_id || '—', {
        id: 'worker',
        header: t('supremeNerveCenter.colWorker'),
        cell: ({ getValue }) => <span className="font-mono text-[10px] text-[var(--text-muted)]">{getValue()}</span>,
      }),
    ]
  }, [t])

  const stuckEngines = useMemo(
    () => engines.filter((e) => e.lifecycle === 'stuck'),
    [engines],
  )

  const handleExport = useCallback(async () => {
    if (!snap) return
    const blob = new Blob([JSON.stringify(snap, null, 2)], { type: 'application/json' })
    const url = URL.createObjectURL(blob)
    const a = document.createElement('a')
    a.href = url
    a.download = `supreme-nerve-center-${Date.now()}.json`
    a.click()
    URL.revokeObjectURL(url)
  }, [snap])

  const sectionLabel = (id) => t(`supremeNerveCenter.sections.${id}`, id)

  return (
    <div className="flex min-h-screen bg-[var(--bg-0)] text-[var(--text-secondary)]">
      <aside className="flex w-56 shrink-0 flex-col border-r border-[var(--border-default)] bg-[#030712]/90">
        <div className="border-b border-[var(--border-default)] p-4">
          <div className="flex items-center gap-2 text-emerald-400">
            <Zap className="h-5 w-5" />
            <span className="text-sm font-semibold tracking-wide">
              {t('supremeNerveCenter.title')}
            </span>
          </div>
          <p className="mt-1 text-[10px] font-mono uppercase tracking-widest text-[var(--text-muted)]">
            {t('supremeNerveCenter.ceoOnly')}
          </p>
        </div>
        <nav className="flex-1 space-y-1 p-2">
          {SECTIONS.map((id) => (
            <Button variant="unstyled"
              key={id}
              type="button"
              onClick={() => setSection(id)}
              className={`w-full rounded-lg px-3 py-2 text-left text-sm transition ${
                section === id
                  ? 'bg-emerald-500/15 text-emerald-300'
                  : 'text-[var(--text-tertiary)] hover:bg-[var(--row-hover-bg)] hover:text-[var(--text-secondary)]'
              }`}
            >
              {sectionLabel(id)}
            </Button>
          ))}
        </nav>
        <div className="border-t border-[var(--border-default)] p-3 text-[10px] font-mono text-[var(--text-muted)]">
          {lastRefresh ? lastRefresh.toLocaleTimeString() : '—'}
          <br />
          {t('supremeNerveCenter.pollInterval', { sec: POLL_MS / 1000 })}
        </div>
      </aside>

      <main className="flex-1 overflow-auto p-6">
        <EvidenceNotice>{t('supremeNerveCenter.evidence_notice', { engines: summary.engines_total ?? PRODUCTION_ENGINE_COUNT })}</EvidenceNotice>

        <header className="mb-6 mt-4 flex flex-wrap items-center justify-between gap-4">
          <div>
            <h1 className="text-xl font-semibold text-white">{sectionLabel(section)}</h1>
          </div>
          <ShellScanActions onRefresh={load} onExport={handleExport} exportDisabled={!snap} />
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
              <div className="rounded-xl border border-[var(--border-default)] bg-[var(--bg-2)] p-4">
                <h2 className="mb-3 text-sm font-medium text-[var(--text-secondary)]">
                  {t('supremeNerveCenter.activeRuns')}
                </h2>
                <div className="max-h-64 space-y-2 overflow-auto">
                  {engines
                    .filter((e) => e.lifecycle === 'running' || e.lifecycle === 'stuck')
                    .slice(0, 20)
                    .map((e) => (
                      <div
                        key={`${e.engine_id}-${e.job_id}`}
                        className="rounded border border-[var(--border-subtle)] bg-[var(--row-hover-bg)] px-3 py-2 text-xs"
                      >
                        <div className="flex justify-between gap-2">
                          <span className="font-mono text-cyan-300">{e.engine_id}</span>
                          <span style={{ color: lifecycleTone(e.lifecycle) }}>{e.lifecycle}</span>
                        </div>
                        <div className="mt-1 text-[var(--text-muted)]">
                          {e.phase}
                          {e.phase_detail ? ` · ${e.phase_detail}` : ''}
                        </div>
                        <div className="mt-1 font-mono text-[10px] text-[var(--text-muted)]">
                          {formatMs(e.elapsed_ms)} · {e.target || '—'}
                        </div>
                      </div>
                    ))}
                  {!engines.some((e) => e.lifecycle === 'running' || e.lifecycle === 'stuck') ? (
                    <p className="text-xs text-[var(--text-muted)]">{t('supremeNerveCenter.noActiveRuns')}</p>
                  ) : null}
                </div>
              </div>

              <div className="rounded-xl border border-[var(--border-default)] bg-[var(--bg-2)] p-4">
                <h2 className="mb-3 text-sm font-medium text-[var(--text-secondary)]">
                  {t('supremeNerveCenter.clientBoot')}
                </h2>
                {clientBoot ? (
                  <dl className="space-y-2 text-xs">
                    <div className="flex justify-between">
                      <dt className="text-[var(--text-muted)]">{t('supremeNerveCenter.documentReady')}</dt>
                      <dd className="font-mono">{clientBoot.document_ready}</dd>
                    </div>
                    <div className="flex justify-between">
                      <dt className="text-[var(--text-muted)]">{t('supremeNerveCenter.domMs')}</dt>
                      <dd className="font-mono">{clientBoot.navigation_ms}ms</dd>
                    </div>
                    <div className="flex justify-between">
                      <dt className="text-[var(--text-muted)]">SW</dt>
                      <dd className="font-mono">{clientBoot.sw_controller ? 'active' : 'none'}</dd>
                    </div>
                    <div className="flex justify-between">
                      <dt className="text-[var(--text-muted)]">{t('supremeNerveCenter.chunksLoaded')}</dt>
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
                <Search className="absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-[var(--text-muted)]" />
                <input
                  type="search"
                  value={searchQuery}
                  onChange={(e) => setSearchQuery(e.target.value)}
                  aria-label={t('supremeNerveCenter.searchEngines')}
                  placeholder={t('supremeNerveCenter.searchEngines')}
                  className="w-full rounded-lg border border-[var(--border-default)] bg-[var(--bg-2)] py-2 pl-9 pr-3 text-sm text-[var(--text-secondary)] placeholder:text-[var(--text-muted)]"
                />
              </div>
              <select
                value={lifecycleFilter}
                onChange={(e) => setLifecycleFilter(e.target.value)}
                className="rounded-lg border border-[var(--border-default)] bg-[var(--bg-2)] px-3 py-2 text-sm text-[var(--text-secondary)]"
              >
                <option value="all">{t('supremeNerveCenter.filterAll')}</option>
                <option value="running">{t('supremeNerveCenter.filterRunning')}</option>
                <option value="stuck">{t('supremeNerveCenter.filterStuck')}</option>
                <option value="idle">{t('supremeNerveCenter.filterIdle')}</option>
                <option value="failed">{t('supremeNerveCenter.filterFailed')}</option>
              </select>
            </div>

            <DataTable
              columns={engineColumns}
              data={filteredEngines}
              loading={loading && !snap}
              animateRows={false}
              getRowId={(e) => e.engine_id}
              tableClassName="min-w-[900px]"
              exportable
              exportFilename="weissman-engine-lifecycle"
              columnToggle
              emptyState={{ icon: 'inbox', title: t('supremeNerveCenter.filterAll') }}
            />
            <p className="px-1 pt-2 text-[10px] text-[var(--text-muted)]">
              {t('supremeNerveCenter.engineCount', {
                shown: filteredEngines.length,
                total: engines.length,
              })}
            </p>
          </div>
        )}

        {section === 'modules' && (
          <div className="grid gap-4 md:grid-cols-2 xl:grid-cols-3">
            {modules.map((m) => (
              <div
                key={m.id}
                className="rounded-xl border border-[var(--border-default)] bg-[var(--bg-2)] p-4 backdrop-blur-sm"
              >
                <div className="mb-2 flex items-start justify-between gap-2">
                  <div>
                    <h3 className="text-sm font-medium text-[var(--text-secondary)]">{m.label}</h3>
                    <span className="text-[10px] font-mono uppercase text-[var(--text-muted)]">{m.category}</span>
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
                <p className="mb-3 text-xs leading-relaxed text-[var(--text-muted)]">{m.description}</p>
                <dl className="space-y-1 text-[11px]">
                  <div className="flex justify-between">
                    <dt className="text-[var(--text-muted)]">{t('supremeNerveCenter.moduleLoaded')}</dt>
                    <dd>{m.loaded ? t('supremeNerveCenter.yes') : t('supremeNerveCenter.no')}</dd>
                  </div>
                  <div className="flex justify-between">
                    <dt className="text-[var(--text-muted)]">{t('supremeNerveCenter.modulePhase')}</dt>
                    <dd className="font-mono">{m.phase}</dd>
                  </div>
                </dl>
                {m.metrics && Object.keys(m.metrics).length > 0 ? (
                  <pre className="mt-3 max-h-24 overflow-auto rounded bg-[var(--bg-3)] p-2 text-[10px] text-[var(--text-muted)]">
                    {JSON.stringify(m.metrics, null, 2)}
                  </pre>
                ) : null}
              </div>
            ))}

            {clientBoot?.script_chunks?.length ? (
              <div className="rounded-xl border border-dashed border-[var(--border-default)] bg-[var(--bg-1)] p-4 md:col-span-2 xl:col-span-3">
                <h3 className="mb-3 flex items-center gap-2 text-sm text-[var(--text-secondary)]">
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
          <DataTable
            columns={jobColumns}
            data={jobs}
            loading={loading && !snap}
            animateRows={false}
            getRowId={(j) => j.id}
            tableClassName="min-w-[800px]"
            emptyState={{ icon: 'inbox', title: t('supremeNerveCenter.noJobs') }}
          />
        )}

        {section === 'controls' && (
          <div className="grid gap-4 md:grid-cols-2">
            <div className="rounded-xl border border-[var(--border-default)] bg-[var(--bg-2)] p-4">
              <h2 className="mb-3 flex items-center gap-2 text-sm text-[var(--text-secondary)]">
                <Shield className="h-4 w-4" />
                {t('supremeNerveCenter.controlParams')}
              </h2>
              <dl className="space-y-2 text-xs">
                {Object.entries(controls).map(([k, v]) => (
                  <div key={k} className="flex justify-between gap-4 border-b border-[var(--border-subtle)] py-1.5">
                    <dt className="font-mono text-[var(--text-muted)]">{k}</dt>
                    <dd className="font-mono text-[var(--text-secondary)]">{String(v)}</dd>
                  </div>
                ))}
              </dl>
            </div>
            <div className="rounded-xl border border-[var(--border-default)] bg-[var(--bg-2)] p-4">
              <h2 className="mb-3 flex items-center gap-2 text-sm text-[var(--text-secondary)]">
                <Server className="h-4 w-4" />
                {t('supremeNerveCenter.ceoTelemetry')}
              </h2>
              <pre className="max-h-96 overflow-auto text-[10px] text-[var(--text-muted)]">
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
