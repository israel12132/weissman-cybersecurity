/**
 * UEBA — User & Entity Behavior Analytics.
 *
 * Live tenant data from GET /api/ueba/anomalies, /api/ueba/fleet, /api/ueba/policy
 * and /api/ueba/whitelist. Disposition posts to POST /api/ueba/anomalies/:id/disposition.
 * Policy writes PUT /api/ueba/policy. Whitelist writes POST/DELETE /api/ueba/whitelist.
 * Route: /ueba
 */
import { useState, useCallback, useEffect, useMemo } from 'react'
import { useTranslation } from 'react-i18next'
import { createColumnHelper } from '@tanstack/react-table'
import { Activity, Search } from 'lucide-react'
import PageShell from './PageShell'
import EmptyState from '../components/ui/EmptyState'
import EvidenceNotice from '../components/ui/EvidenceNotice'
import ExecutiveWidget from '../components/ui/ExecutiveWidget'
import DataTable from '../components/ui/DataTable'
import CopyButton from '../components/ui/CopyButton'
import FilterPills from '../components/ui/FilterPills'
import { SkeletonWidgetGrid } from '../components/ui/Skeleton'
import ShellScanActions from '../components/engine/ShellScanActions'
import { useClient } from '../context/ClientContext'
import { usePermissions } from '../context/AuthContext'
import { apiFetch } from '../utils/apiFetch'
import { SEV_ORDER, SEV_COLOR } from '../lib/severity'
import { downloadCsv } from '../lib/exportFindingsCsv'
import Button from '../components/ui/Button'

const NS = 'pages.uebaAnomalies'
const columnHelper = createColumnHelper()

function zColor(z) {
  const a = Math.abs(Number(z) || 0)
  if (a >= 4) return '#f43f5e'
  if (a >= 3) return '#f97316'
  if (a >= 2) return '#facc15'
  return '#38bdf8'
}

function fmtNum(n) {
  const v = Number(n)
  if (!Number.isFinite(v)) return '—'
  return Math.abs(v) >= 1000 ? v.toLocaleString(undefined, { maximumFractionDigits: 1 }) : v.toFixed(2)
}

function fmtWhen(iso) {
  if (!iso) return '—'
  const d = new Date(iso)
  return Number.isNaN(d.getTime()) ? '—' : d.toLocaleString()
}

function anomaliesCsv(rows) {
  const header = [
    'agent_id', 'metric_name', 'observed', 'baseline_mean', 'baseline_stddev',
    'z_score', 'severity', 'status', 'weighted_score', 'detected_at',
  ]
  const data = rows.map((r) => [
    r.agent_id, r.metric_name, r.observed, r.baseline_mean, r.baseline_stddev,
    r.z_score, r.severity, r.status, r.weighted_score, r.detected_at,
  ])
  downloadCsv(data, header, 'weissman-ueba-anomalies')
}

export default function UebaAnomalies() {
  const { t } = useTranslation()
  const { clients } = useClient()
  const { hasRole } = usePermissions()
  const canDispose = hasRole('analyst')
  const canOperate = hasRole('operator')
  const [anomalies, setAnomalies] = useState([])
  const [fleet, setFleet] = useState([])
  const [policy, setPolicy] = useState(null)
  const [whitelist, setWhitelist] = useState([])
  const [tab, setTab] = useState('anomalies')
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState('')
  const [search, setSearch] = useState('')
  const [sevFilter, setSevFilter] = useState('all')
  const [wlName, setWlName] = useState('')
  const [wlReason, setWlReason] = useState('')
  const [learnWindow, setLearnWindow] = useState(7)
  const [bizStart, setBizStart] = useState(8)
  const [bizEnd, setBizEnd] = useState(18)

  const load = useCallback(async () => {
    setLoading(true)
    setError('')
    try {
      const [d, f, p, w] = await Promise.all([
        apiFetch('/api/ueba/anomalies?limit=500'),
        apiFetch('/api/ueba/fleet'),
        apiFetch('/api/ueba/policy'),
        apiFetch('/api/ueba/whitelist'),
      ])
      if (d?.ok === false) throw new Error(d.detail || 'load failed')
      setAnomalies(Array.isArray(d.anomalies) ? d.anomalies : [])
      setFleet(Array.isArray(f?.agents) ? f.agents : [])
      const pol = p?.policy || p
      setPolicy(pol && typeof pol === 'object' ? pol : null)
      if (pol?.learn_window_days) setLearnWindow(Number(pol.learn_window_days) || 7)
      if (pol?.business_hours_start != null) setBizStart(Number(pol.business_hours_start) || 8)
      if (pol?.business_hours_end != null) setBizEnd(Number(pol.business_hours_end) || 18)
      setWhitelist(Array.isArray(w?.items) ? w.items : [])
    } catch (e) {
      setError(e.message || t(`${NS}.load_failed`))
    } finally {
      setLoading(false)
    }
  }, [t])

  useEffect(() => {
    load()
  }, [load])

  const severities = useMemo(
    () => [...new Set(anomalies.map((a) => (a.severity || '').toLowerCase()).filter(Boolean))].sort(
      (a, b) => (SEV_ORDER[b] || 0) - (SEV_ORDER[a] || 0),
    ),
    [anomalies],
  )

  const filtered = useMemo(() => {
    const q = search.trim().toLowerCase()
    return anomalies.filter((a) => {
      if (sevFilter !== 'all' && (a.severity || '').toLowerCase() !== sevFilter) return false
      if (!q) return true
      return `${a.agent_id} ${a.metric_name} ${a.detail} ${a.status}`.toLowerCase().includes(q)
    })
  }, [anomalies, search, sevFilter])

  const stats = useMemo(() => {
    const agents = new Set()
    let critHigh = 0
    let maxZ = 0
    for (const a of anomalies) {
      if (a.agent_id) agents.add(a.agent_id)
      const s = (a.severity || '').toLowerCase()
      if (s === 'critical' || s === 'high') critHigh += 1
      const z = Math.abs(Number(a.z_score) || 0)
      if (z > maxZ) maxZ = z
    }
    const learning = fleet.filter((a) => a.is_learning).length
    return { total: anomalies.length, agents: agents.size, critHigh, maxZ, learning, fleet: fleet.length }
  }, [anomalies, fleet])

  const sevPills = useMemo(
    () => [
      { id: 'all', label: t(`${NS}.all_severities`), active: sevFilter === 'all', onClick: () => setSevFilter('all') },
      ...severities.map((s) => ({
        id: s,
        label: s,
        active: sevFilter === s,
        onClick: () => setSevFilter(s),
      })),
    ],
    [severities, sevFilter, t],
  )

  const dispose = useCallback(
    async (id, status) => {
      if (!canDispose) return
      await apiFetch(`/api/ueba/anomalies/${id}/disposition`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ status, reason: status }),
      })
      load()
    },
    [canDispose, load],
  )

  const savePolicy = useCallback(async () => {
    if (!canOperate) return
    await apiFetch('/api/ueba/policy', {
      method: 'PUT',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        learn_window_days: Number(learnWindow) || 7,
        business_hours_start: Number(bizStart) || 8,
        business_hours_end: Number(bizEnd) || 18,
        treat_holidays_as_weekend: true,
      }),
    })
    load()
  }, [canOperate, learnWindow, bizStart, bizEnd, load])

  const addWhitelist = useCallback(async () => {
    if (!canOperate || !wlName.trim()) return
    await apiFetch('/api/ueba/whitelist', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ process_name: wlName.trim(), reason: wlReason.trim() }),
    })
    setWlName('')
    setWlReason('')
    load()
  }, [canOperate, wlName, wlReason, load])

  const removeWhitelist = useCallback(
    async (id) => {
      if (!canOperate) return
      await apiFetch(`/api/ueba/whitelist/${id}`, { method: 'DELETE' })
      load()
    },
    [canOperate, load],
  )

  const clientName = useMemo(() => {
    const byId = new Map((clients || []).map((c) => [String(c.id), c.name || c.domain]))
    return (id) => (id ? byId.get(String(id)) : null)
  }, [clients])

  const columns = useMemo(
    () => [
      columnHelper.accessor((a) => a.agent_id || '', {
        id: 'agent_id',
        header: t(`${NS}.col_agent`),
        cell: (ctx) => {
          const cname = clientName(ctx.row.original.client_id)
          return (
            <div className="min-w-0">
              <span className="flex items-center gap-1.5 min-w-0">
                <code className="text-[12px] text-[var(--text-primary)] font-mono truncate max-w-[14rem]" title={ctx.getValue()}>
                  {ctx.getValue() || '—'}
                </code>
                {ctx.getValue() && <CopyButton value={ctx.getValue()} />}
              </span>
              {cname && (
                <span className="block text-[10px] font-mono text-[var(--text-muted)] truncate max-w-[14rem]" title={cname}>
                  {cname}
                </span>
              )}
            </div>
          )
        },
      }),
      columnHelper.accessor((a) => a.metric_name || '', {
        id: 'metric_name',
        header: t(`${NS}.col_metric`),
        cell: (ctx) => (
          <span className="text-[10px] font-mono px-2 py-0.5 rounded border border-violet-500/25 bg-violet-500/5 text-violet-300/85">
            {ctx.getValue() || '—'}
          </span>
        ),
      }),
      columnHelper.accessor((a) => Number(a.observed) || 0, {
        id: 'observed',
        header: t(`${NS}.col_observed`),
        cell: (ctx) => {
          const a = ctx.row.original
          return (
            <span className="text-[12px] font-mono whitespace-nowrap">
              <span className="text-[var(--text-primary)]">{fmtNum(a.observed)}</span>
              <span className="text-[var(--text-muted)]"> {t(`${NS}.vs`)} </span>
              <span className="text-[var(--text-tertiary)]">{fmtNum(a.baseline_mean)}</span>
              <span className="text-[var(--text-muted)] text-[10px]"> ±{fmtNum(a.baseline_stddev)}</span>
            </span>
          )
        },
      }),
      columnHelper.accessor((a) => Math.abs(Number(a.z_score) || 0), {
        id: 'z_score',
        header: t(`${NS}.col_z`),
        cell: (ctx) => {
          const z = Number(ctx.row.original.z_score) || 0
          const c = zColor(z)
          return (
            <span
              className="text-[11px] font-mono px-1.5 py-0.5 rounded border tabular-nums whitespace-nowrap"
              style={{ color: c, borderColor: `${c}40`, background: `${c}12` }}
            >
              {z >= 0 ? '+' : ''}
              {z.toFixed(2)}σ
            </span>
          )
        },
      }),
      columnHelper.accessor((a) => (a.severity || 'info').toLowerCase(), {
        id: 'severity',
        header: t(`${NS}.col_severity`),
        cell: (ctx) => {
          const s = ctx.getValue()
          const c = SEV_COLOR[s] || SEV_COLOR.info
          return (
            <span
              className="text-[9px] font-mono px-1.5 py-0.5 rounded border uppercase tracking-wider"
              style={{ color: c, borderColor: `${c}40`, background: `${c}10` }}
            >
              {s}
            </span>
          )
        },
        sortingFn: (a, b) => (SEV_ORDER[a.getValue('severity')] || 0) - (SEV_ORDER[b.getValue('severity')] || 0),
      }),
      columnHelper.accessor((a) => a.detail || '', {
        id: 'detail',
        header: t(`${NS}.col_detail`),
        enableSorting: false,
        cell: (ctx) => (
          <span className="text-[var(--text-tertiary)] text-[12px] block max-w-[24rem] truncate" title={ctx.getValue()}>
            {ctx.getValue() || '—'}
          </span>
        ),
      }),
      columnHelper.accessor((a) => a.detected_at || '', {
        id: 'detected_at',
        header: t(`${NS}.col_detected`),
        cell: (ctx) => (
          <span className="text-[var(--text-muted)] whitespace-nowrap text-[11px]">
            {fmtWhen(ctx.getValue())}
          </span>
        ),
      }),
      columnHelper.accessor((a) => a.status || 'open', {
        id: 'status',
        header: t(`${NS}.col_status`),
        cell: (ctx) => {
          const row = ctx.row.original
          return (
            <div className="flex items-center gap-2">
              <span className="text-[10px] font-mono uppercase text-[var(--text-muted)]">{ctx.getValue()}</span>
              {canDispose && (row.status || 'open') === 'open' && (
                <span className="flex gap-1">
                  <Button size="sm" variant="ghost" onClick={() => dispose(row.id, 'false_positive')}>
                    {t(`${NS}.mark_fp`)}
                  </Button>
                  <Button size="sm" variant="ghost" onClick={() => dispose(row.id, 'approved')}>
                    {t(`${NS}.mark_approved`)}
                  </Button>
                </span>
              )}
            </div>
          )
        },
      }),
    ],
    [t, clientName, canDispose, dispose],
  )

  return (
    <PageShell
      title={t(`${NS}.title`)}
      subtitle={t(`${NS}.subtitle`)}
      badge={t(`${NS}.badge`)}
      badgeColor="#a78bfa"
      icon={<Activity className="w-5 h-5" />}
      actions={
        <ShellScanActions
          onRefresh={load}
          onExport={() => anomaliesCsv(filtered)}
          refreshLoading={loading}
          exportDisabled={!filtered.length}
        />
      }
    >
      <div className="space-y-6">
        <EvidenceNotice>{t(`${NS}.evidence_notice`)}</EvidenceNotice>

        <div className="flex flex-wrap gap-2" role="tablist" aria-label={t(`${NS}.title`)}>
          {['anomalies', 'fleet', 'policy'].map((id) => (
            <button
              key={id}
              type="button"
              role="tab"
              aria-selected={tab === id}
              onClick={() => setTab(id)}
              className={`px-3 py-1.5 rounded-lg text-[11px] font-mono uppercase tracking-wider border ${
                tab === id
                  ? 'border-violet-500/50 bg-violet-500/15 text-violet-200'
                  : 'border-[var(--border-default)] text-[var(--text-muted)]'
              }`}
            >
              {t(`${NS}.tab_${id}`)}
            </button>
          ))}
        </div>

        {loading && <SkeletonWidgetGrid count={5} />}

        {error && (
          <div role="alert" className="rounded-xl border border-rose-500/30 bg-rose-950/20 px-4 py-3 text-sm text-rose-300 font-mono">
            {error}
          </div>
        )}

        {!loading && !error && (
          <>
            <div className="grid grid-cols-2 sm:grid-cols-5 gap-3">
              <ExecutiveWidget label={t(`${NS}.kpi_total`)} value={stats.total} accent="#a78bfa" />
              <ExecutiveWidget label={t(`${NS}.kpi_agents`)} value={stats.agents} accent="#22d3ee" />
              <ExecutiveWidget label={t(`${NS}.kpi_crit_high`)} value={stats.critHigh} accent="#f43f5e" />
              <ExecutiveWidget label={t(`${NS}.kpi_max_z`)} value={`${stats.maxZ.toFixed(1)}σ`} accent="#f97316" />
              <ExecutiveWidget label={t(`${NS}.kpi_learning`)} value={stats.learning} accent="#eab308" />
            </div>

            {stats.learning > 0 && (
              <div className="rounded-xl border border-amber-500/25 bg-amber-950/20 px-4 py-3 text-[12px] font-mono text-amber-200/90">
                {t(`${NS}.learning_banner`)}
              </div>
            )}

            {tab === 'anomalies' && (
              <>
                <div className="flex flex-wrap items-center gap-3">
                  <div className="relative flex-1 min-w-[220px] max-w-md">
                    <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-[var(--text-disabled)] pointer-events-none" />
                    <input
                      type="search"
                      value={search}
                      onChange={(e) => setSearch(e.target.value)}
                      aria-label={t(`${NS}.search_placeholder`)}
                      placeholder={t(`${NS}.search_placeholder`)}
                      className="w-full bg-[var(--bg-3)] border border-[var(--border-default)] rounded-xl pl-10 pr-3 py-2 text-sm text-[var(--text-primary)] placeholder-[var(--text-muted)] focus:outline-none focus:border-violet-500/40"
                    />
                  </div>
                  {severities.length > 0 && <FilterPills pills={sevPills} />}
                </div>

                {anomalies.length === 0 ? (
                  <EmptyState icon="chart" title={t(`${NS}.empty_title`)} body={t(`${NS}.empty_body`)} />
                ) : filtered.length === 0 ? (
                  <EmptyState icon="search-x" title={t(`${NS}.no_match_title`)} body={t(`${NS}.no_match_body`)} />
                ) : (
                  <DataTable
                    id="ueba-anomalies-table"
                    columns={columns}
                    data={filtered}
                    animateRows={false}
                    getRowId={(a) => a.id}
                    getRowAccentColor={(a) => SEV_COLOR[(a.severity || 'info').toLowerCase()]}
                  />
                )}
              </>
            )}

            {tab === 'fleet' && (
              <div className="overflow-x-auto rounded-xl border border-[var(--border-default)]">
                <table className="w-full text-left text-[12px] font-mono">
                  <thead className="text-[10px] uppercase text-[var(--text-muted)]">
                    <tr>
                      <th className="px-3 py-2">{t(`${NS}.col_agent`)}</th>
                      <th className="px-3 py-2">{t(`${NS}.col_host`)}</th>
                      <th className="px-3 py-2">{t(`${NS}.col_learning`)}</th>
                      <th className="px-3 py-2">{t(`${NS}.col_anomalies_24h`)}</th>
                      <th className="px-3 py-2">{t(`${NS}.col_last_seen`)}</th>
                    </tr>
                  </thead>
                  <tbody>
                    {fleet.map((a) => (
                      <tr key={a.agent_id} className="border-t border-[var(--border-default)]">
                        <td className="px-3 py-2 truncate max-w-[14rem]">{a.agent_id}</td>
                        <td className="px-3 py-2">{a.hostname || '—'}</td>
                        <td className="px-3 py-2">{a.is_learning ? t(`${NS}.learning_yes`) : t(`${NS}.learning_no`)}</td>
                        <td className="px-3 py-2">{a.anomalies_24h ?? 0}</td>
                        <td className="px-3 py-2">{fmtWhen(a.last_seen_at)}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
                {fleet.length === 0 && (
                  <EmptyState icon="chart" title={t(`${NS}.empty_fleet_title`)} body={t(`${NS}.empty_fleet_body`)} />
                )}
              </div>
            )}

            {tab === 'policy' && (
              <div className="space-y-6 max-w-2xl">
                {policy?.learn_window_days != null && (
                  <p className="text-[11px] font-mono text-[var(--text-muted)]">
                    {t(`${NS}.learn_window`)}: {policy.learn_window_days}
                  </p>
                )}
                <div className="grid grid-cols-1 sm:grid-cols-3 gap-3">
                  <label className="text-[11px] font-mono text-[var(--text-muted)]">
                    {t(`${NS}.learn_window`)}
                    <select
                      value={learnWindow}
                      onChange={(e) => setLearnWindow(Number(e.target.value))}
                      disabled={!canOperate}
                      className="mt-1 w-full bg-[var(--bg-3)] border border-[var(--border-default)] rounded-lg px-2 py-1.5 text-[var(--text-primary)]"
                    >
                      <option value={7}>7</option>
                      <option value={14}>14</option>
                      <option value={30}>30</option>
                    </select>
                  </label>
                  <label className="text-[11px] font-mono text-[var(--text-muted)]">
                    {t(`${NS}.biz_start`)}
                    <input
                      type="number"
                      min={0}
                      max={23}
                      value={bizStart}
                      onChange={(e) => setBizStart(Number(e.target.value))}
                      disabled={!canOperate}
                      className="mt-1 w-full bg-[var(--bg-3)] border border-[var(--border-default)] rounded-lg px-2 py-1.5 text-[var(--text-primary)]"
                    />
                  </label>
                  <label className="text-[11px] font-mono text-[var(--text-muted)]">
                    {t(`${NS}.biz_end`)}
                    <input
                      type="number"
                      min={1}
                      max={24}
                      value={bizEnd}
                      onChange={(e) => setBizEnd(Number(e.target.value))}
                      disabled={!canOperate}
                      className="mt-1 w-full bg-[var(--bg-3)] border border-[var(--border-default)] rounded-lg px-2 py-1.5 text-[var(--text-primary)]"
                    />
                  </label>
                </div>
                {canOperate && (
                  <Button onClick={savePolicy}>{t(`${NS}.save_policy`)}</Button>
                )}
                <div className="space-y-2">
                  <div className="text-[11px] font-mono uppercase text-[var(--text-muted)]">{t(`${NS}.whitelist`)}</div>
                  {canOperate && (
                    <div className="flex flex-wrap gap-2">
                      <input
                        value={wlName}
                        onChange={(e) => setWlName(e.target.value)}
                        placeholder={t(`${NS}.wl_name`)}
                        className="bg-[var(--bg-3)] border border-[var(--border-default)] rounded-lg px-2 py-1.5 text-sm"
                      />
                      <input
                        value={wlReason}
                        onChange={(e) => setWlReason(e.target.value)}
                        placeholder={t(`${NS}.wl_reason`)}
                        className="bg-[var(--bg-3)] border border-[var(--border-default)] rounded-lg px-2 py-1.5 text-sm"
                      />
                      <Button onClick={addWhitelist}>{t(`${NS}.wl_add`)}</Button>
                    </div>
                  )}
                  <ul className="space-y-1 font-mono text-[12px]">
                    {whitelist.map((w) => (
                      <li key={w.id} className="flex items-center justify-between gap-2 border border-[var(--border-default)] rounded-lg px-3 py-1.5">
                        <span>{w.process_name} {w.reason ? `— ${w.reason}` : ''}</span>
                        {canOperate && (
                          <Button size="sm" variant="ghost" onClick={() => removeWhitelist(w.id)}>
                            {t(`${NS}.wl_remove`)}
                          </Button>
                        )}
                      </li>
                    ))}
                  </ul>
                </div>
              </div>
            )}
          </>
        )}
      </div>
    </PageShell>
  )
}
