import { useState, useEffect, useMemo, useCallback } from 'react'
import { useTranslation } from 'react-i18next'
import { Activity, ShieldCheck, Cpu, AlertTriangle, Globe, WifiOff } from 'lucide-react'
import PageShell from './PageShell'
import ShellScanActions from '../components/engine/ShellScanActions'
import WeissmanFindingsPanel from '../components/engine/WeissmanFindingsPanel'
import { useFindingsWorkbench } from '../hooks/useFindingsWorkbench'
import { SkeletonWidgetGrid } from '../components/ui/Skeleton'
import EngineRealityBadge, { REALITY_KIND_META, EngineRealitySummary } from '../components/EngineRealityBadge'
import { useEngineCapabilities } from '../lib/useEngineCapabilities'
import { api } from '../utils/apiFetch'

const KIND_FILTERS = ['all', 'real_probe', 'alias', 'agent_required', 'special']

function statusColor(s) {
  if (s === 'ok') return '#34d399'
  if (s === 'timeout') return '#f59e0b'
  if (s === 'panic' || s === 'error') return '#ef4444'
  return '#6b7280'
}

function formatTs(ts) {
  if (!ts) return '—'
  const d = new Date(ts * 1000)
  if (Number.isNaN(d.getTime())) return '—'
  return d.toLocaleString()
}

function severityFromRow(r) {
  const h = r.health
  const failed = h?.failed_runs ?? 0
  if (failed >= 3) return 'critical'
  if (failed > 0) return 'high'
  if (h?.last_status === 'error' || h?.last_status === 'panic') return 'high'
  if (h?.last_status === 'timeout') return 'medium'
  if (h && h.total_runs > 0) return 'low'
  return 'info'
}

function StatCard({ label, value, tone, icon, hint }) {
  return (
    <div className="bg-black/40 backdrop-blur-md border border-white/10 rounded-xl p-4" title={hint}>
      <div className="flex items-center justify-between mb-2">
        <span className="text-xs text-gray-400">{label}</span>
        {icon}
      </div>
      <div className="text-2xl font-bold" style={tone ? { color: tone } : { color: '#fff' }}>
        {value}
      </div>
    </div>
  )
}

export default function EngineReliability() {
  const { t } = useTranslation()
  const { byId, summary, total, legend, remoteDetectionCount, loading: capsLoading, error: capsError, refresh: refreshCaps } =
    useEngineCapabilities()
  const [telem, setTelem] = useState(null)
  const [telemLoading, setTelemLoading] = useState(true)
  const [telemError, setTelemError] = useState(null)
  const [kindFilter, setKindFilter] = useState('all')
  const [onlyRuns, setOnlyRuns] = useState(false)
  const [onlyRemote, setOnlyRemote] = useState(false)

  const loadTelem = useCallback(async () => {
    try {
      setTelemError(null)
      setTelem(await api.get('/api/engines/telemetry'))
    } catch (e) {
      setTelemError(e?.message || 'Failed to load telemetry')
    } finally {
      setTelemLoading(false)
    }
  }, [])

  useEffect(() => {
    loadTelem()
  }, [loadTelem])

  useEffect(() => {
    const id = setInterval(loadTelem, 8000)
    return () => clearInterval(id)
  }, [loadTelem])

  const refreshAll = useCallback(() => {
    refreshCaps()
    loadTelem()
  }, [refreshCaps, loadTelem])

  const telemById = useMemo(() => {
    const m = {}
    for (const e of telem?.engines || []) m[e.engine_id] = e
    return m
  }, [telem])

  const rows = useMemo(() => {
    const list = Object.values(byId).map((c) => ({ ...c, health: telemById[c.id] || null }))
    const filtered = list.filter(
      (r) =>
        (kindFilter === 'all' || r.kind === kindFilter) &&
        (!onlyRuns || (r.health && r.health.total_runs > 0)) &&
        (!onlyRemote || r.remote_detection),
    )
    filtered.sort((a, b) => {
      const ar = a.health?.updated_ts || 0
      const br = b.health?.updated_ts || 0
      if (ar !== br) return br - ar
      return a.id.localeCompare(b.id)
    })
    return filtered
  }, [byId, telemById, kindFilter, onlyRuns, onlyRemote])

  const rowFindings = useMemo(() => rows.map((r) => {
    const h = r.health
    const parts = []
    if (h?.last_status) parts.push(h.last_status)
    if (h?.last_error) parts.push(h.last_error)
    if (h) {
      parts.push(`${h.total_runs ?? 0} runs · ${h.recovered_runs ?? 0} self-heal · ${h.failed_runs ?? 0} failed`)
    } else {
      parts.push('never run')
    }
    return {
      id: r.id,
      severity: severityFromRow(r),
      title: r.id,
      type: r.kind,
      description: parts.join(' · '),
      _row: r,
    }
  }), [rows])

  const {
    filteredFindings,
    counts,
    searchQuery,
    setSearchQuery,
    severityFilter,
    setSeverityFilter,
    exportCsv,
    total: findingsTotal,
  } = useFindingsWorkbench(rowFindings, {
    csvPrefix: 'engine-reliability',
    haystackFn: (f) => {
      const r = f._row
      return `${f.title} ${f.type} ${f.description} ${r?.canonical || ''} ${r?.health?.last_strategy || ''}`
    },
  })

  const recoveryRate =
    telem && telem.total_runs > 0 ? Math.round((telem.recovered_runs / telem.total_runs) * 100) : 0

  const loading = capsLoading && !total

  return (
    <PageShell
      title={t('pages.engineReliability.title', { defaultValue: 'Engine Reliability' })}
      icon={<Activity />}
      actions={(
        <ShellScanActions
          onRefresh={refreshAll}
          onExport={exportCsv}
          refreshLoading={loading || telemLoading}
          exportDisabled={!filteredFindings.length}
        />
      )}
    >
      <div className="space-y-6">
        <div className="space-y-2 max-w-2xl">
          <p className="text-sm text-gray-400">
            {t('pages.engineReliability.subtitle', {
              defaultValue:
                'Fleet health for every engine: reality classification plus live run telemetry — attempts, self-heal recoveries, failures, and last-run latency. Auto-refreshing.',
            })}
          </p>
          <EngineRealitySummary compact />
        </div>

        {(capsError || telemError) && (
          <div className="flex items-center gap-2 text-xs text-amber-300 bg-amber-500/10 border border-amber-500/20 rounded-lg px-3 py-2">
            <AlertTriangle className="w-4 h-4 shrink-0" />
            {[capsError, telemError].filter(Boolean).join(' · ')}
          </div>
        )}

        {loading ? (
          <div className="rounded-2xl bg-black/40 border border-white/10 p-6">
            <SkeletonWidgetGrid count={8} />
          </div>
        ) : (
          <>
            <div className="grid grid-cols-2 md:grid-cols-4 lg:grid-cols-8 gap-3">
              <StatCard
                label={t('pages.engineReliability.total_engines', { defaultValue: 'Engine IDs' })}
                value={total}
                icon={<Cpu className="w-4 h-4 text-cyan-400" />}
              />
              <StatCard
                label={t('pages.engineReliability.remote_capable', { defaultValue: 'Remote detect' })}
                value={remoteDetectionCount}
                tone="#22d3ee"
                icon={<Globe className="w-4 h-4 text-cyan-400" />}
                hint="Engines that can detect from a remote scan without an agent"
              />
              <StatCard
                label={t('pages.engineReliability.real_probes', { defaultValue: 'Live probes' })}
                value={summary.real_probe ?? 0}
                tone="#34d399"
              />
              <StatCard
                label={t('pages.engineReliability.aliases', { defaultValue: 'Aliases' })}
                value={summary.alias ?? 0}
                tone="#9ca3af"
              />
              <StatCard
                label={t('pages.engineReliability.agent_required', { defaultValue: 'Agent-required' })}
                value={summary.agent_required ?? 0}
                tone="#f59e0b"
                icon={<WifiOff className="w-4 h-4 text-amber-400" />}
              />
              <StatCard
                label={t('pages.engineReliability.engines_observed', { defaultValue: 'Engines with runs' })}
                value={telem?.engines_observed ?? 0}
                icon={<Activity className="w-4 h-4 text-purple-400" />}
              />
              <StatCard
                label={t('pages.engineReliability.total_runs', { defaultValue: 'Runs observed' })}
                value={telem?.total_runs ?? 0}
              />
              <StatCard
                label={t('pages.engineReliability.recovery_rate', { defaultValue: 'Self-heal rate' })}
                value={`${recoveryRate}%`}
                tone="#34d399"
                icon={<ShieldCheck className="w-4 h-4 text-emerald-400" />}
              />
            </div>

            {(telem?.failed_runs ?? 0) > 0 && (
              <div className="flex items-center gap-2 text-xs text-amber-300 bg-amber-500/10 border border-amber-500/20 rounded-lg px-3 py-2">
                <AlertTriangle className="w-4 h-4" />
                {t('pages.engineReliability.failed_note', {
                  defaultValue:
                    '{{failed}} run(s) exhausted all strategies (isolated — they never stopped other engines).',
                  failed: telem.failed_runs,
                })}
              </div>
            )}

            {Object.keys(legend).length > 0 && (
              <details className="bg-black/30 border border-white/10 rounded-lg px-4 py-3 text-xs text-gray-400">
                <summary className="cursor-pointer font-mono uppercase tracking-wider text-gray-500 select-none">
                  {t('pages.engineReliability.legend', { defaultValue: 'Reality legend (from API)' })}
                </summary>
                <ul className="mt-3 space-y-1.5 font-mono">
                  {Object.entries(legend).map(([k, desc]) => (
                    <li key={k} className="flex items-start gap-2">
                      <EngineRealityBadge kind={k} size="sm" />
                      <span>{desc}</span>
                    </li>
                  ))}
                </ul>
              </details>
            )}

            <div className="flex items-center gap-3 flex-wrap">
              <div className="flex items-center gap-1.5 bg-black/40 border border-white/10 rounded-lg p-1">
                {KIND_FILTERS.map((k) => (
                  <button
                    key={k}
                    type="button"
                    onClick={() => setKindFilter(k)}
                    className={`px-2.5 py-1 rounded-md text-[11px] font-medium transition-all ${
                      kindFilter === k
                        ? 'bg-cyan-500/20 text-cyan-300 border border-cyan-500/30'
                        : 'text-gray-400 hover:text-white'
                    }`}
                  >
                    {k === 'all'
                      ? t('pages.engineReliability.all', { defaultValue: 'All' })
                      : (REALITY_KIND_META[k]?.label ?? k)}
                  </button>
                ))}
              </div>
              <label className="flex items-center gap-2 text-xs text-gray-400 cursor-pointer">
                <input
                  type="checkbox"
                  checked={onlyRuns}
                  onChange={(e) => setOnlyRuns(e.target.checked)}
                  className="accent-cyan-500"
                />
                {t('pages.engineReliability.only_runs', { defaultValue: 'Only engines that have run' })}
              </label>
              <label className="flex items-center gap-2 text-xs text-gray-400 cursor-pointer">
                <input
                  type="checkbox"
                  checked={onlyRemote}
                  onChange={(e) => setOnlyRemote(e.target.checked)}
                  className="accent-cyan-500"
                />
                {t('pages.engineReliability.only_remote', { defaultValue: 'Remote detection only' })}
              </label>
              <span className="text-[11px] font-mono text-gray-500 ml-auto">
                {rows.length} {t('pages.engineReliability.shown', { defaultValue: 'shown' })}
                {telemLoading && !telem ? ' · telemetry…' : ''}
              </span>
            </div>

            <WeissmanFindingsPanel
              findings={rowFindings}
              filteredFindings={filteredFindings}
              counts={counts}
              total={findingsTotal}
              searchQuery={searchQuery}
              onSearchChange={setSearchQuery}
              severityFilter={severityFilter}
              onSeverityChange={setSeverityFilter}
              accent="#22d3ee"
              title={t('pages.engineReliability.col_engine', { defaultValue: 'Engine fleet' })}
              emptyTitle={t('pages.engineReliability.no_match', { defaultValue: 'No engines match filters' })}
              emptyBody={t('pages.engineReliability.search_ph', { defaultValue: 'Filter engines…' })}
              renderFinding={(f) => {
                const r = f._row
                if (!r) return null
                const h = r.health
                return (
                  <div key={r.id} className="rounded-lg border border-white/[0.06] bg-black/30 px-4 py-2.5 hover:bg-white/[0.03]">
                    <div className="flex flex-wrap items-start gap-x-4 gap-y-2">
                      <div className="min-w-[180px] flex-1 font-mono text-white/85 text-xs">
                        {r.id}
                        {r.canonical && (
                          <span className="text-gray-500"> → {r.canonical}</span>
                        )}
                      </div>
                      <div className="shrink-0">
                        <EngineRealityBadge kind={r.kind} canonical={r.canonical} remoteDetection={r.remote_detection} size="sm" />
                      </div>
                      <div className="shrink-0 text-center w-8">
                        {r.remote_detection ? (
                          <Globe className="w-3.5 h-3.5 text-cyan-400 inline-block" title="Remote detection" />
                        ) : (
                          <WifiOff className="w-3.5 h-3.5 text-amber-500/80 inline-block" title="Agent required" />
                        )}
                      </div>
                      <div className="font-mono text-xs text-white/70 text-right w-12">{h?.total_runs ?? '—'}</div>
                      <div className="font-mono text-xs text-right w-12" style={{ color: h?.recovered_runs ? '#34d399' : '#6b7280' }}>
                        {h?.recovered_runs ?? '—'}
                      </div>
                      <div className="font-mono text-xs text-right w-12" style={{ color: h?.failed_runs ? '#ef4444' : '#6b7280' }}>
                        {h?.failed_runs ?? '—'}
                      </div>
                      <div className="min-w-[200px] flex-1">
                        {h ? (
                          <div className="flex flex-col gap-0.5">
                            <span className="flex items-center gap-2">
                              <span
                                className="inline-block w-2 h-2 rounded-full shrink-0"
                                style={{ backgroundColor: statusColor(h.last_status) }}
                              />
                              <span className="text-xs text-white/60">{h.last_status}</span>
                              <span className="text-[10px] font-mono text-gray-500">
                                {h.last_attempts}× · {h.last_elapsed_ms}ms
                              </span>
                            </span>
                            {h.last_strategy && (
                              <span className="text-[10px] font-mono text-gray-600 truncate max-w-[220px]" title={h.last_strategy}>
                                {h.last_strategy}
                              </span>
                            )}
                            {h.last_error && (
                              <span className="text-[10px] font-mono text-red-400/80 truncate max-w-[220px]" title={h.last_error}>
                                {h.last_error}
                              </span>
                            )}
                            <span className="text-[9px] font-mono text-gray-600">{formatTs(h.updated_ts)}</span>
                          </div>
                        ) : (
                          <span className="text-xs text-gray-600">{t('pages.engineReliability.never_run', { defaultValue: 'never run' })}</span>
                        )}
                      </div>
                    </div>
                  </div>
                )
              }}
            />
          </>
        )}
      </div>
    </PageShell>
  )
}
