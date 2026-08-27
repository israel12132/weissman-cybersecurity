/**
 * Finding Clusters — SOC inbox of correlated detections.
 *
 * Live GET /api/findings/clusters. One card per sha256(target|signature|cwe).
 * Severity is native member-max unless corroboration boosts it: network + agent
 * on the same identity jumps the cluster to Critical.
 * Route: /finding-clusters
 */
import { useState, useCallback, useEffect, useMemo } from 'react'
import { Link, useSearchParams } from 'react-router'
import { useTranslation } from 'react-i18next'
import { createColumnHelper } from '@tanstack/react-table'
import { Layers, Search } from 'lucide-react'
import PageShell from './PageShell'
import EmptyState from '../components/ui/EmptyState'
import EvidenceNotice from '../components/ui/EvidenceNotice'
import ExecutiveWidget from '../components/ui/ExecutiveWidget'
import DataTable from '../components/ui/DataTable'
import FilterPills from '../components/ui/FilterPills'
import { SkeletonWidgetGrid } from '../components/ui/Skeleton'
import ShellScanActions from '../components/engine/ShellScanActions'
import SeverityBadge from '../components/ui/SeverityBadge'
import { apiFetch } from '../utils/apiFetch'
import { downloadCsv } from '../lib/exportFindingsCsv'
import {
  BOOST_CROSS,
  BOOST_MULTI,
  CLUSTERS_CSV_HEADER,
  boostColor,
  boostLabel,
  clustersCsv,
  isCorroborated,
  planesLabel,
} from '../lib/clusterCorroboration'

const NS = 'pages.findingClusters'
const columnHelper = createColumnHelper()

export default function FindingClusters() {
  const { t } = useTranslation()
  const [searchParams] = useSearchParams()
  const highlightId = Number(searchParams.get('id') || 0) || null

  const [rows, setRows] = useState([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState('')
  const [search, setSearch] = useState('')
  const [sevFilter, setSevFilter] = useState('all')
  const [boostFilter, setBoostFilter] = useState('all')

  const load = useCallback(async () => {
    setLoading(true)
    setError('')
    try {
      const d = await apiFetch('/api/findings/clusters?limit=1000')
      if (d?.ok === false) throw new Error(d.detail || 'load failed')
      setRows(Array.isArray(d.clusters) ? d.clusters : [])
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
    const total = rows.length
    const critical = rows.filter((r) => String(r.max_severity).toLowerCase() === 'critical').length
    const cross = rows.filter((r) => r.corroboration_boost === BOOST_CROSS).length
    const multi = rows.filter((r) => r.corroboration_boost === BOOST_MULTI).length
    return { total, critical, cross, multi }
  }, [rows])

  const filtered = useMemo(() => {
    const q = search.trim().toLowerCase()
    return rows.filter((r) => {
      if (sevFilter !== 'all' && String(r.max_severity).toLowerCase() !== sevFilter) return false
      if (boostFilter === 'boosted' && !isCorroborated(r.corroboration_boost)) return false
      if (boostFilter === BOOST_CROSS && r.corroboration_boost !== BOOST_CROSS) return false
      if (boostFilter === BOOST_MULTI && r.corroboration_boost !== BOOST_MULTI) return false
      if (!q) return true
      const hay = [
        r.title,
        r.target,
        r.vuln_signature,
        r.cwe,
        ...(r.engines || []),
        ...(r.engine_planes || []),
        r.corroboration_boost,
      ]
        .filter(Boolean)
        .join(' ')
        .toLowerCase()
      return hay.includes(q)
    })
  }, [rows, search, sevFilter, boostFilter])

  const columns = useMemo(
    () => [
      columnHelper.accessor((r) => r.max_severity || 'info', {
        id: 'severity',
        header: t(`${NS}.col_severity`),
        cell: (ctx) => {
          const r = ctx.row.original
          return (
            <span className="inline-flex flex-col gap-1">
              <SeverityBadge severity={r.max_severity} />
              {isCorroborated(r.corroboration_boost) && r.native_severity && r.native_severity !== r.max_severity && (
                <span className="text-[9px] font-mono text-[var(--text-muted)]">
                  {t(`${NS}.boosted_from`, { native: r.native_severity })}
                </span>
              )}
              {r.watermark_severity && r.watermark_severity === r.max_severity && r.native_severity && r.native_severity !== r.watermark_severity && (
                <span className="text-[9px] font-mono uppercase tracking-wider text-rose-300/80">
                  {t(`${NS}.watermark_held`)}
                </span>
              )}
            </span>
          )
        },
      }),
      columnHelper.accessor((r) => r.corroboration_boost || 'none', {
        id: 'boost',
        header: t(`${NS}.col_boost`),
        cell: (ctx) => {
          const boost = ctx.getValue()
          const color = boostColor(boost)
          return (
            <span
              className="inline-flex items-center px-2 py-0.5 rounded text-[10px] font-mono uppercase tracking-wider"
              style={{ color, backgroundColor: `${color}18`, border: `1px solid ${color}40` }}
            >
              {boostLabel(boost, t)}
            </span>
          )
        },
      }),
      columnHelper.accessor((r) => planesLabel(r.engine_planes), {
        id: 'planes',
        header: t(`${NS}.col_planes`),
        cell: (ctx) => (
          <span className="text-[11px] font-mono text-cyan-300/80">{ctx.getValue()}</span>
        ),
      }),
      columnHelper.accessor((r) => (r.engines || []).join(', '), {
        id: 'engines',
        header: t(`${NS}.col_engines`),
        cell: (ctx) => (
          <span className="text-[11px] font-mono text-[var(--text-secondary)] max-w-[220px] truncate block">
            {ctx.getValue() || '—'}
          </span>
        ),
      }),
      columnHelper.accessor((r) => r.title || r.vuln_signature || '', {
        id: 'title',
        header: t(`${NS}.col_title`),
        cell: (ctx) => {
          const r = ctx.row.original
          return (
            <div className="min-w-0">
              <div className="text-sm text-[var(--text-primary)] truncate">{r.title || '—'}</div>
              <div className="text-[10px] font-mono text-[var(--text-muted)] truncate">
                {r.vuln_signature}
                {r.cwe ? ` · ${r.cwe}` : ''}
              </div>
            </div>
          )
        },
      }),
      columnHelper.accessor((r) => r.target || '', {
        id: 'target',
        header: t(`${NS}.col_target`),
        cell: (ctx) => (
          <span className="text-[11px] font-mono text-[var(--text-tertiary)] max-w-[240px] truncate block">
            {ctx.getValue() || '—'}
          </span>
        ),
      }),
      columnHelper.accessor((r) => r.member_count || 0, {
        id: 'members',
        header: t(`${NS}.col_members`),
        cell: (ctx) => (
          <span className="text-[11px] font-mono text-amber-200/90">{ctx.getValue()}</span>
        ),
      }),
      columnHelper.accessor((r) => r.status || '', {
        id: 'status',
        header: t(`${NS}.col_status`),
        cell: (ctx) => (
          <span className="text-[10px] font-mono uppercase text-[var(--text-muted)]">{ctx.getValue()}</span>
        ),
      }),
    ],
    [t],
  )

  return (
    <PageShell
      title={t(`${NS}.title`)}
      subtitle={t(`${NS}.subtitle`)}
      badge={t(`${NS}.badge`)}
      badgeColor="#f43f5e"
      icon={<Layers className="w-5 h-5" />}
      actions={
        <ShellScanActions
          onRefresh={load}
          onExport={() => downloadCsv(clustersCsv(filtered), CLUSTERS_CSV_HEADER, 'weissman-finding-clusters')}
          refreshLoading={loading}
          exportDisabled={!filtered.length}
        />
      }
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
            <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
              <ExecutiveWidget label={t(`${NS}.kpi_total`)} value={stats.total} accent="#22d3ee" />
              <ExecutiveWidget label={t(`${NS}.kpi_critical`)} value={stats.critical} accent="#f43f5e" />
              <ExecutiveWidget label={t(`${NS}.kpi_cross`)} value={stats.cross} accent="#fb7185" />
              <ExecutiveWidget label={t(`${NS}.kpi_multi`)} value={stats.multi} accent="#f59e0b" />
            </div>

            <div className="flex flex-wrap items-center justify-between gap-3">
              <FilterPills
                label={t(`${NS}.filter_severity`)}
                pills={['all', 'critical', 'high', 'medium', 'low', 'info'].map((s) => ({
                  id: `cluster-sev-${s}`,
                  label: s === 'all' ? t(`${NS}.filter_all`) : s,
                  active: sevFilter === s,
                  color: s === 'critical' ? '#f43f5e' : '#94a3b8',
                  onClick: () => setSevFilter(s),
                }))}
              />
              <div className="flex items-center gap-2 text-[11px] font-mono">
                <Link to="/findings" className="text-cyan-400/80 hover:text-cyan-300">
                  {t(`${NS}.link_findings`)}
                </Link>
                <span className="text-[var(--text-disabled)]">·</span>
                <Link to="/suppressions" className="text-cyan-400/80 hover:text-cyan-300">
                  {t(`${NS}.link_suppressions`)}
                </Link>
              </div>
            </div>

            <div className="flex flex-wrap items-center gap-3">
              <div className="relative flex-1 min-w-[220px] max-w-md">
                <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-[var(--text-disabled)] pointer-events-none" />
                <input
                  type="search"
                  value={search}
                  onChange={(e) => setSearch(e.target.value)}
                  aria-label={t(`${NS}.search_placeholder`)}
                  placeholder={t(`${NS}.search_placeholder`)}
                  className="w-full bg-[var(--bg-3)] border border-[var(--border-default)] rounded-xl pl-10 pr-3 py-2 text-sm text-[var(--text-primary)] placeholder-[var(--text-muted)] focus:outline-none focus:border-cyan-500/40"
                />
              </div>
              <div className="flex items-center gap-1 shrink-0" role="group" aria-label={t(`${NS}.filter_boost`)}>
                {[
                  ['all', t(`${NS}.filter_all`)],
                  ['boosted', t(`${NS}.filter_boosted`)],
                  [BOOST_CROSS, t(`${NS}.boost_cross_plane`)],
                  [BOOST_MULTI, t(`${NS}.boost_multi_engine`)],
                ].map(([id, label]) => (
                  <button
                    key={id}
                    type="button"
                    onClick={() => setBoostFilter(id)}
                    aria-pressed={boostFilter === id}
                    className={[
                      'px-2.5 py-1.5 rounded-lg text-[10px] font-mono uppercase tracking-wider border transition-colors',
                      boostFilter === id
                        ? 'bg-rose-500/15 text-rose-200 border-rose-500/30'
                        : 'text-[var(--text-muted)] border-[var(--border-default)] hover:text-[var(--text-secondary)]',
                    ].join(' ')}
                  >
                    {label}
                  </button>
                ))}
              </div>
            </div>

            {filtered.length === 0 ? (
              rows.length === 0 ? (
                <EmptyState icon="inbox" title={t(`${NS}.empty_title`)} body={t(`${NS}.empty_body`)} />
              ) : (
                <EmptyState icon="search-x" title={t(`${NS}.no_match_title`)} body={t(`${NS}.no_match_body`)} />
              )
            ) : (
              <DataTable
                id="finding-clusters-table"
                columns={columns}
                data={filtered}
                selectedRowId={highlightId}
              />
            )}
          </>
        )}
      </div>
    </PageShell>
  )
}
