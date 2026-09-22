/**
 * UEBA Entity Risk — decayed, explainable per-entity risk + peer-group outliers.
 *
 * Wired to:
 *   GET /api/ueba/entity-risk    — entities ranked by time-decayed risk score
 *   GET /api/ueba/peer-anomalies — hosts deviating from their cohort (median+MAD)
 * Route: /command-center/entity-risk
 */
import { useState, useCallback, useEffect, useMemo } from 'react'
import { useTranslation } from 'react-i18next'
import { createColumnHelper } from '@tanstack/react-table'
import { Activity, Search, Users } from 'lucide-react'
import PageShell from './PageShell'
import EmptyState from '../components/ui/EmptyState'
import EvidenceNotice from '../components/ui/EvidenceNotice'
import ExecutiveWidget from '../components/ui/ExecutiveWidget'
import FilterPills from '../components/ui/FilterPills'
import DataTable from '../components/ui/DataTable'
import { SkeletonWidgetGrid } from '../components/ui/Skeleton'
import ShellScanActions from '../components/engine/ShellScanActions'
import { apiFetch } from '../utils/apiFetch'
import { SEV_ORDER, SEV_COLOR, normalizeSeverity } from '../lib/severity'
import { downloadCsv } from '../lib/exportFindingsCsv'

const NS = 'pages.entityRisk'
const columnHelper = createColumnHelper()
const SEV_KEYS = ['critical', 'high', 'medium', 'low', 'info']

export default function EntityRisk() {
  const { t } = useTranslation()
  const [entities, setEntities] = useState([])
  const [outliers, setOutliers] = useState([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState('')
  const [sevFilter, setSevFilter] = useState('all')
  const [search, setSearch] = useState('')

  const load = useCallback(async () => {
    setLoading(true)
    setError('')
    try {
      const [er, pa] = await Promise.all([
        apiFetch('/api/ueba/entity-risk?limit=100'),
        apiFetch('/api/ueba/peer-anomalies?limit=100').catch(() => ({ outliers: [] })),
      ])
      if (er?.ok === false) throw new Error(er.detail || 'load failed')
      setEntities(Array.isArray(er?.entities) ? er.entities : [])
      setOutliers(Array.isArray(pa?.outliers) ? pa.outliers : [])
    } catch (e) {
      setError(e.message || t(`${NS}.load_failed`))
    } finally {
      setLoading(false)
    }
  }, [t])

  useEffect(() => {
    load()
  }, [load])

  const stats = useMemo(() => {
    let critHigh = 0
    let maxScore = 0
    for (const e of entities) {
      const s = (e.severity || '').toLowerCase()
      if (s === 'critical' || s === 'high') critHigh += 1
      maxScore = Math.max(maxScore, Number(e.risk_score) || 0)
    }
    return { total: entities.length, critHigh, maxScore, outliers: outliers.length }
  }, [entities, outliers])

  const sevCounts = useMemo(() => {
    const c = { all: entities.length, critical: 0, high: 0, medium: 0, low: 0, info: 0 }
    for (const e of entities) c[normalizeSeverity(e.severity)] += 1
    return c
  }, [entities])

  const displayEntities = useMemo(() => {
    const q = search.trim().toLowerCase()
    return entities.filter((e) => {
      if (sevFilter !== 'all' && normalizeSeverity(e.severity) !== sevFilter) return false
      if (!q) return true
      return `${e.entity_id || ''} ${e.entity_type || ''}`.toLowerCase().includes(q)
    })
  }, [entities, sevFilter, search])

  const sevPills = useMemo(
    () =>
      [
        { id: 'all', label: t('common.all'), count: sevCounts.all, color: '#06b6d4' },
        ...SEV_KEYS.filter((s) => sevCounts[s] > 0).map((s) => ({
          id: s,
          label: t(`severity.${s}`),
          count: sevCounts[s],
          color: SEV_COLOR[s] || SEV_COLOR.info,
        })),
      ].map((p) => ({ ...p, active: sevFilter === p.id, onClick: () => setSevFilter(p.id) })),
    [sevCounts, sevFilter, t],
  )

  const exportCsv = useCallback(() => {
    const header = ['entity_type', 'entity_id', 'risk_score', 'peak_score', 'severity', 'event_count', 'last_event_at']
    const data = entities.map((e) => [
      e.entity_type, e.entity_id, e.risk_score, e.peak_score, e.severity, e.event_count, e.last_event_at,
    ])
    downloadCsv(data, header, 'weissman-entity-risk')
  }, [entities])

  const entityColumns = useMemo(
    () => [
      columnHelper.accessor((e) => e.entity_id || '', {
        id: 'entity',
        header: t(`${NS}.col_entity`),
        cell: (ctx) => (
          <span className="flex items-center gap-2 min-w-0">
            <span className="text-[9px] font-mono px-1.5 py-0.5 rounded border border-cyan-500/25 text-cyan-300/70 uppercase">
              {ctx.row.original.entity_type || 'agent'}
            </span>
            <code className="text-[12px] text-[var(--text-primary)] font-mono truncate max-w-[18rem]" title={ctx.getValue()}>
              {ctx.getValue() || '—'}
            </code>
          </span>
        ),
      }),
      columnHelper.accessor((e) => Number(e.risk_score) || 0, {
        id: 'risk',
        header: t(`${NS}.col_risk`),
        cell: (ctx) => {
          const v = ctx.getValue()
          const pct = Math.min(100, v)
          const c = v >= 90 ? '#f43f5e' : v >= 60 ? '#f97316' : v >= 30 ? '#f59e0b' : '#64748b'
          return (
            <span className="flex items-center gap-2 min-w-[120px]">
              <span className="flex-1 h-1.5 rounded-full bg-[var(--bg-4)] overflow-hidden max-w-[90px]">
                <span className="block h-full rounded-full" style={{ width: `${Math.max(4, pct)}%`, background: c }} />
              </span>
              <span className="text-[12px] font-mono font-semibold" style={{ color: c }}>{v}</span>
            </span>
          )
        },
      }),
      columnHelper.accessor((e) => (e.severity || 'info').toLowerCase(), {
        id: 'severity',
        header: t(`${NS}.col_severity`),
        cell: (ctx) => {
          const s = ctx.getValue()
          const c = SEV_COLOR[s] || SEV_COLOR.info
          return (
            <span className="text-[9px] font-mono px-1.5 py-0.5 rounded border uppercase tracking-wider" style={{ color: c, borderColor: `${c}40`, background: `${c}10` }}>
              {s}
            </span>
          )
        },
        sortingFn: (a, b) => (SEV_ORDER[a.getValue('severity')] || 0) - (SEV_ORDER[b.getValue('severity')] || 0),
      }),
      columnHelper.accessor((e) => e.event_count || 0, {
        id: 'events',
        header: t(`${NS}.col_events`),
        cell: (ctx) => <span className="text-[12px] font-mono text-[var(--text-tertiary)]">{ctx.getValue()}</span>,
      }),
      columnHelper.display({
        id: 'contributors',
        header: t(`${NS}.col_contributors`),
        enableSorting: false,
        cell: (ctx) => {
          const cs = Array.isArray(ctx.row.original.contributors) ? ctx.row.original.contributors.slice(0, 3) : []
          if (!cs.length) return <span className="text-[var(--text-muted)] text-[11px]">—</span>
          return (
            <span className="flex flex-wrap gap-1">
              {cs.map((c, i) => (
                <span key={i} className="text-[10px] font-mono px-1.5 py-0.5 rounded border border-[var(--border-default)] text-[var(--text-tertiary)]" title={`+${c.weight}`}>
                  {String(c.signal || '').slice(0, 28)}
                </span>
              ))}
            </span>
          )
        },
      }),
      columnHelper.accessor((e) => e.last_event_at || '', {
        id: 'last',
        header: t(`${NS}.col_last`),
        cell: (ctx) => (
          <span className="text-[var(--text-muted)] whitespace-nowrap text-[11px]">
            {ctx.getValue() ? new Date(ctx.getValue()).toLocaleString() : '—'}
          </span>
        ),
      }),
    ],
    [t],
  )

  const outlierColumns = useMemo(
    () => [
      columnHelper.accessor((o) => o.agent_id || '', {
        id: 'agent',
        header: t(`${NS}.col_agent`),
        cell: (ctx) => <code className="text-[12px] text-[var(--text-primary)] font-mono truncate max-w-[16rem]" title={ctx.getValue()}>{ctx.getValue() || '—'}</code>,
      }),
      columnHelper.accessor((o) => o.metric || '', {
        id: 'metric',
        header: t(`${NS}.col_metric`),
        cell: (ctx) => <span className="text-[12px] font-mono text-cyan-300/80">{ctx.getValue()}</span>,
      }),
      columnHelper.accessor((o) => o.cohort || '', {
        id: 'cohort',
        header: t(`${NS}.col_cohort`),
        cell: (ctx) => <span className="text-[11px] font-mono text-[var(--text-tertiary)]">{ctx.getValue()}</span>,
      }),
      columnHelper.accessor((o) => Number(o.observed) || 0, {
        id: 'observed',
        header: t(`${NS}.col_observed`),
        cell: (ctx) => (
          <span className="text-[12px] font-mono text-[var(--text-primary)]">
            {ctx.getValue()} <span className="text-[var(--text-muted)]">({t(`${NS}.median`)} {ctx.row.original.cohort_median})</span>
          </span>
        ),
      }),
      columnHelper.accessor((o) => Number(o.modified_z) || 0, {
        id: 'z',
        header: t(`${NS}.col_z`),
        cell: (ctx) => {
          const z = ctx.getValue()
          const c = Math.abs(z) >= 6 ? '#f43f5e' : '#f59e0b'
          return <span className="text-[12px] font-mono font-semibold" style={{ color: c }}>{z}</span>
        },
      }),
    ],
    [t],
  )

  return (
    <PageShell
      title={t(`${NS}.title`)}
      subtitle={t(`${NS}.subtitle`)}
      badge={t(`${NS}.badge`)}
      badgeColor="#06b6d4"
      icon={<Activity className="w-5 h-5" />}
      actions={<ShellScanActions onRefresh={load} onExport={exportCsv} refreshLoading={loading} exportDisabled={!entities.length} />}
    >
      <div className="space-y-6">
        <EvidenceNotice>{t(`${NS}.evidence_notice`)}</EvidenceNotice>

        {loading && <SkeletonWidgetGrid count={4} />}

        {error && (
          <div role="alert" className="rounded-xl border border-rose-500/30 bg-rose-950/20 px-4 py-3 text-sm text-rose-300 font-mono">
            {error}
          </div>
        )}

        {!loading && !error && (
          <>
            <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
              <ExecutiveWidget label={t(`${NS}.kpi_entities`)} value={stats.total} accent="#06b6d4" />
              <ExecutiveWidget label={t(`${NS}.kpi_crit_high`)} value={stats.critHigh} accent="#f43f5e" />
              <ExecutiveWidget label={t(`${NS}.kpi_max`)} value={stats.maxScore} accent="#f97316" />
              <ExecutiveWidget label={t(`${NS}.kpi_outliers`)} value={stats.outliers} accent="#a78bfa" />
            </div>

            <section>
              <h3 className="text-sm font-semibold text-[var(--text-primary)] mb-2">{t(`${NS}.entities_title`)}</h3>
              {entities.length === 0 ? (
                <EmptyState icon="chart" title={t(`${NS}.empty_title`)} body={t(`${NS}.empty_body`)} />
              ) : (
                <>
                  <div className="flex flex-wrap items-end gap-4 mb-3">
                    <div className="relative flex-1 min-w-[220px] max-w-sm">
                      <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-3.5 h-3.5 text-[var(--text-muted)] pointer-events-none" />
                      <input
                        type="search"
                        value={search}
                        onChange={(e) => setSearch(e.target.value)}
                        aria-label={t(`${NS}.search_placeholder`)}
                        placeholder={t(`${NS}.search_placeholder`)}
                        className="w-full pl-9 pr-3 py-2 rounded-lg text-sm bg-[var(--bg-3)] border border-[var(--border-default)] text-[var(--text-primary)] placeholder-[var(--text-muted)] focus:outline-none focus:border-cyan-500/40"
                      />
                    </div>
                    <FilterPills pills={sevPills} />
                  </div>
                  {displayEntities.length === 0 ? (
                    <EmptyState icon="search-x" title={t(`${NS}.no_match_title`)} body={t(`${NS}.no_match_body`)} />
                  ) : (
                    <DataTable
                      id="entity-risk-table"
                      columns={entityColumns}
                      data={displayEntities}
                      animateRows={false}
                      getRowId={(e) => `${e.entity_type}:${e.entity_id}`}
                      getRowAccentColor={(e) => SEV_COLOR[(e.severity || 'info').toLowerCase()]}
                    />
                  )}
                </>
              )}
            </section>

            <section>
              <h3 className="flex items-center gap-2 text-sm font-semibold text-[var(--text-primary)] mb-2">
                <Users className="w-4 h-4 text-cyan-400/70" />
                {t(`${NS}.peers_title`)}
              </h3>
              {outliers.length === 0 ? (
                <EmptyState icon="network" title={t(`${NS}.peers_empty_title`)} body={t(`${NS}.peers_empty_body`)} />
              ) : (
                <DataTable
                  id="peer-outliers-table"
                  columns={outlierColumns}
                  data={outliers}
                  animateRows={false}
                  getRowId={(o) => `${o.agent_id}:${o.metric}:${o.cohort}`}
                />
              )}
            </section>
          </>
        )}
      </div>
    </PageShell>
  )
}
