/**
 * UEBA — User & Entity Behavior Analytics anomalies.
 *
 * Wired to the live GET /api/ueba/anomalies endpoint, which surfaces
 * per-agent behavioral anomalies from the `agent_anomalies` table: each row
 * is a metric whose observed value deviated from its rolling baseline
 * (mean/stddev), scored by z-score and severity. Route: /ueba
 *
 * Ingest pipeline counters come from GET /api/ueba/ingest-stats (PostgreSQL
 * binary COPY worker — replica-local queued depth, rows flushed, last flush,
 * backpressure rejects, schema version).
 *
 * Optional query params the endpoint accepts: `limit` (1–500) and `agent_id`.
 * We fetch the default page and filter/search client-side over the result.
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
import { apiFetch } from '../utils/apiFetch'
import { SEV_ORDER, SEV_COLOR } from '../lib/severity'
import { downloadCsv } from '../lib/exportFindingsCsv'

const NS = 'pages.uebaAnomalies'
const columnHelper = createColumnHelper()

/** Colour a z-score by how far it sits from the baseline. */
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

function anomaliesCsv(rows) {
  const header = ['agent_id', 'metric_name', 'observed', 'baseline_mean', 'baseline_stddev', 'z_score', 'severity', 'detected_at']
  const data = rows.map((r) => [
    r.agent_id, r.metric_name, r.observed, r.baseline_mean, r.baseline_stddev, r.z_score, r.severity, r.detected_at,
  ])
  downloadCsv(data, header, 'weissman-ueba-anomalies')
}

export default function UebaAnomalies() {
  const { t } = useTranslation()
  const { clients } = useClient()
  const [anomalies, setAnomalies] = useState([])
  const [ingest, setIngest] = useState(null)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState('')
  const [search, setSearch] = useState('')
  const [sevFilter, setSevFilter] = useState('all')

  const load = useCallback(async () => {
    setLoading(true)
    setError('')
    try {
      const [d, statsResp] = await Promise.all([
        apiFetch('/api/ueba/anomalies?limit=500'),
        apiFetch('/api/ueba/ingest-stats').catch(() => null),
      ])
      if (d?.ok === false) throw new Error(d.detail || 'load failed')
      setAnomalies(Array.isArray(d.anomalies) ? d.anomalies : [])
      setIngest(statsResp?.ok && statsResp.stats ? statsResp.stats : null)
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
      return `${a.agent_id} ${a.metric_name} ${a.detail}`.toLowerCase().includes(q)
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
    return { total: anomalies.length, agents: agents.size, critHigh, maxZ }
  }, [anomalies])

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

  // Resolve an anomaly's client id → name for at-a-glance tenant context.
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
            {ctx.getValue() ? new Date(ctx.getValue()).toLocaleString() : '—'}
          </span>
        ),
      }),
    ],
    [t, clientName],
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

        {loading && <SkeletonWidgetGrid count={8} />}

        {error && (
          <div role="alert" className="rounded-xl border border-rose-500/30 bg-rose-950/20 px-4 py-3 text-sm text-rose-300 font-mono">
            {error}
          </div>
        )}

        {!loading && !error && (
          <>
            <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
              <ExecutiveWidget label={t(`${NS}.kpi_total`)} value={stats.total} accent="#a78bfa" />
              <ExecutiveWidget label={t(`${NS}.kpi_agents`)} value={stats.agents} accent="#22d3ee" />
              <ExecutiveWidget label={t(`${NS}.kpi_crit_high`)} value={stats.critHigh} accent="#f43f5e" />
              <ExecutiveWidget label={t(`${NS}.kpi_max_z`)} value={`${stats.maxZ.toFixed(1)}σ`} accent="#f97316" />
            </div>

            {ingest && (
              <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-5 gap-3">
                <ExecutiveWidget
                  label={t(`${NS}.kpi_copy_mode`)}
                  value={
                    ingest.copy_enabled
                      ? t(`${NS}.copy_mode_live`)
                      : ingest.copy_fallback_inserts > 0
                        ? t(`${NS}.copy_mode_insert`)
                        : t(`${NS}.copy_mode_idle`)
                  }
                  hint={ingest.copy_enabled ? 'PGCOPY binary' : 'INSERT'}
                  accent={ingest.copy_enabled ? '#34d399' : '#94a3b8'}
                />
                <ExecutiveWidget
                  label={t(`${NS}.kpi_copy_rows`)}
                  value={Number(ingest.copy_rows_flushed || 0).toLocaleString()}
                  hint={`${Number(ingest.copy_flushes || 0).toLocaleString()} flushes`}
                  accent="#22d3ee"
                />
                <ExecutiveWidget
                  label={t(`${NS}.kpi_copy_flush`)}
                  value={`${Number(ingest.copy_last_flush_ms || 0)} ms`}
                  hint={`batch ${ingest.copy_batch_size || '—'} · ${ingest.copy_flush_interval_ms || '—'} ms`}
                  accent="#a78bfa"
                />
                <ExecutiveWidget
                  label={t(`${NS}.kpi_copy_queued`)}
                  value={Number(ingest.copy_channel_queued || 0).toLocaleString()}
                  hint={
                    Number(ingest.copy_fallback_inserts || 0) > 0
                      ? `${Number(ingest.copy_fallback_inserts).toLocaleString()} INSERT fallback`
                      : `cap ${ingest.copy_channel_cap || '—'}`
                  }
                  accent={Number(ingest.copy_channel_queued || 0) > 0 ? '#facc15' : '#64748b'}
                />
                <ExecutiveWidget
                  label={t(`${NS}.kpi_copy_backpressure`)}
                  value={Number(ingest.copy_backpressure_rejects || 0).toLocaleString()}
                  hint={
                    ingest.copy_schema_version
                      ? t(`${NS}.kpi_copy_schema`, { version: ingest.copy_schema_version })
                      : t(`${NS}.kpi_copy_backpressure_hint`)
                  }
                  accent={Number(ingest.copy_backpressure_rejects || 0) > 0 ? '#f43f5e' : '#64748b'}
                />
              </div>
            )}

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
      </div>
    </PageShell>
  )
}
