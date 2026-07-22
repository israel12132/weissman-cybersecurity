/**
 * Indicators of Compromise (IOC) feed.
 *
 * Wired to the live GET /api/soc/iocs endpoint, which extracts network IOCs
 * (IPs, domains, URLs, hashes) from persisted findings. Route: /iocs
 */
import { useState, useCallback, useEffect, useMemo } from 'react'
import { Link } from 'react-router-dom'
import { useTranslation } from 'react-i18next'
import { createColumnHelper } from '@tanstack/react-table'
import { Crosshair, Search } from 'lucide-react'
import PageShell from './PageShell'
import EmptyState from '../components/ui/EmptyState'
import EvidenceNotice from '../components/ui/EvidenceNotice'
import ExecutiveWidget from '../components/ui/ExecutiveWidget'
import DataTable from '../components/ui/DataTable'
import CopyButton from '../components/ui/CopyButton'
import FilterPills from '../components/ui/FilterPills'
import { SkeletonWidgetGrid } from '../components/ui/Skeleton'
import ShellScanActions from '../components/engine/ShellScanActions'
import { apiFetch } from '../utils/apiFetch'
import { SEV_ORDER, SEV_COLOR } from '../lib/severity'
import { downloadCsv } from '../lib/exportFindingsCsv'

const NS = 'pages.iocFeed'
const columnHelper = createColumnHelper()

function iocCsv(rows) {
  const header = ['type', 'value', 'severity', 'source', 'added', 'finding_id']
  const data = rows.map((r) => [r.type, r.value, r.severity, r.source, r.added, r.finding_id])
  downloadCsv(data, header, 'weissman-iocs')
}

export default function IocFeed() {
  const { t } = useTranslation()
  const [iocs, setIocs] = useState([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState('')
  const [search, setSearch] = useState('')
  const [typeFilter, setTypeFilter] = useState('all')

  const load = useCallback(async () => {
    setLoading(true)
    setError('')
    try {
      const d = await apiFetch('/api/soc/iocs')
      if (d?.ok === false) throw new Error(d.detail || 'load failed')
      setIocs(Array.isArray(d.iocs) ? d.iocs : [])
    } catch (e) {
      setError(e.message || t(`${NS}.load_failed`))
    } finally {
      setLoading(false)
    }
  }, [t])

  useEffect(() => {
    load()
  }, [load])

  const types = useMemo(
    () => [...new Set(iocs.map((i) => (i.type || '').toLowerCase()).filter(Boolean))].sort(),
    [iocs],
  )

  const filtered = useMemo(() => {
    const q = search.trim().toLowerCase()
    return iocs.filter((i) => {
      if (typeFilter !== 'all' && (i.type || '').toLowerCase() !== typeFilter) return false
      if (!q) return true
      return `${i.value} ${i.type} ${i.source} ${(i.tags || []).join(' ')}`.toLowerCase().includes(q)
    })
  }, [iocs, search, typeFilter])

  const stats = useMemo(() => {
    const byType = {}
    let critHigh = 0
    for (const i of iocs) {
      const ty = (i.type || 'other').toLowerCase()
      byType[ty] = (byType[ty] || 0) + 1
      const s = (i.severity || '').toLowerCase()
      if (s === 'critical' || s === 'high') critHigh += 1
    }
    return { total: iocs.length, types: Object.keys(byType).length, critHigh }
  }, [iocs])

  const typePills = useMemo(
    () => [
      { id: 'all', label: t(`${NS}.all_types`), active: typeFilter === 'all', onClick: () => setTypeFilter('all') },
      ...types.map((ty) => ({
        id: ty,
        label: ty,
        active: typeFilter === ty,
        onClick: () => setTypeFilter(ty),
      })),
    ],
    [types, typeFilter, t],
  )

  const columns = useMemo(
    () => [
      columnHelper.accessor((i) => (i.type || '').toLowerCase(), {
        id: 'type',
        header: t(`${NS}.col_type`),
        cell: (ctx) => (
          <span className="text-[10px] font-mono px-2 py-0.5 rounded border border-cyan-500/25 bg-cyan-500/5 text-cyan-300/80 uppercase">
            {ctx.getValue() || '—'}
          </span>
        ),
      }),
      columnHelper.accessor((i) => i.value || '', {
        id: 'value',
        header: t(`${NS}.col_value`),
        cell: (ctx) => (
          <span className="flex items-center gap-1.5 min-w-0">
            <code className="text-[12px] text-[var(--text-primary)] font-mono truncate max-w-[22rem]" title={ctx.getValue()}>
              {ctx.getValue() || '—'}
            </code>
            {ctx.getValue() && <CopyButton value={ctx.getValue()} />}
          </span>
        ),
      }),
      columnHelper.accessor((i) => (i.severity || 'info').toLowerCase(), {
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
      columnHelper.accessor((i) => i.source || '', {
        id: 'source',
        header: t(`${NS}.col_source`),
        cell: (ctx) => <span className="text-[var(--text-tertiary)] text-[12px]">{ctx.getValue() || '—'}</span>,
      }),
      columnHelper.accessor((i) => i.added || '', {
        id: 'added',
        header: t(`${NS}.col_added`),
        cell: (ctx) => (
          <span className="text-[var(--text-muted)] whitespace-nowrap text-[11px]">
            {ctx.getValue() ? new Date(ctx.getValue()).toLocaleString() : '—'}
          </span>
        ),
      }),
      columnHelper.display({
        id: 'finding',
        header: '',
        enableSorting: false,
        cell: (ctx) =>
          ctx.row.original.finding_id ? (
            <Link
              to="/findings"
              className="text-[11px] font-mono text-cyan-400/80 hover:text-cyan-300 underline underline-offset-2 whitespace-nowrap"
            >
              {t(`${NS}.view_finding`)}
            </Link>
          ) : null,
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
      icon={<Crosshair className="w-5 h-5" />}
      actions={
        <ShellScanActions
          onRefresh={load}
          onExport={() => iocCsv(filtered)}
          refreshLoading={loading}
          exportDisabled={!filtered.length}
        />
      }
    >
      <div className="space-y-6">
        <EvidenceNotice>{t(`${NS}.evidence_notice`)}</EvidenceNotice>

        {loading && <SkeletonWidgetGrid count={3} />}

        {error && (
          <div role="alert" className="rounded-xl border border-rose-500/30 bg-rose-950/20 px-4 py-3 text-sm text-rose-300 font-mono">
            {error}
          </div>
        )}

        {!loading && !error && (
          <>
            <div className="grid grid-cols-3 gap-3">
              <ExecutiveWidget label={t(`${NS}.kpi_total`)} value={stats.total} accent="#22d3ee" />
              <ExecutiveWidget label={t(`${NS}.kpi_types`)} value={stats.types} accent="#a78bfa" />
              <ExecutiveWidget label={t(`${NS}.kpi_crit_high`)} value={stats.critHigh} accent="#f43f5e" />
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
                  className="w-full bg-[var(--bg-3)] border border-[var(--border-default)] rounded-xl pl-10 pr-3 py-2 text-sm text-[var(--text-primary)] placeholder-[var(--text-muted)] focus:outline-none focus:border-rose-500/40"
                />
              </div>
              {types.length > 0 && <FilterPills pills={typePills} />}
            </div>

            {iocs.length === 0 ? (
              <EmptyState icon="target" title={t(`${NS}.empty_title`)} body={t(`${NS}.empty_body`)} />
            ) : filtered.length === 0 ? (
              <EmptyState icon="search-x" title={t(`${NS}.no_match_title`)} body={t(`${NS}.no_match_body`)} />
            ) : (
              <DataTable
                id="ioc-feed-table"
                columns={columns}
                data={filtered}
                animateRows={false}
                getRowId={(i) => i.id}
                getRowAccentColor={(i) => SEV_COLOR[(i.severity || 'info').toLowerCase()]}
              />
            )}
          </>
        )}
      </div>
    </PageShell>
  )
}
