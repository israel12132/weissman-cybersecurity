/**
 * Threat Intelligence Feeds — the live IOC indicator store.
 *
 * Wired to:
 *   GET  /api/ioc/indicators   — normalized multi-source indicator store
 *   GET  /api/ioc/feeds        — feed-run health + store stats
 *   GET  /api/ioc/sightings    — this tenant's IOC sightings
 *   GET  /api/ioc/watchlist    — tenant custom indicators
 *   POST /api/ioc/watchlist    — add a custom indicator
 *   DELETE /api/ioc/watchlist/:id
 *   POST /api/ioc/ingest/run   — trigger a feed-sync job
 * Route: /command-center/threat-feeds
 */
import { useState, useCallback, useEffect, useMemo } from 'react'
import { useTranslation } from 'react-i18next'
import { createColumnHelper } from '@tanstack/react-table'
import { Radar, Search, RefreshCw, Trash2, Plus } from 'lucide-react'
import PageShell from './PageShell'
import EmptyState from '../components/ui/EmptyState'
import EvidenceNotice from '../components/ui/EvidenceNotice'
import ExecutiveWidget from '../components/ui/ExecutiveWidget'
import DataTable from '../components/ui/DataTable'
import CopyButton from '../components/ui/CopyButton'
import FilterPills from '../components/ui/FilterPills'
import { SkeletonWidgetGrid } from '../components/ui/Skeleton'
import ShellScanActions from '../components/engine/ShellScanActions'
import { apiFetch, api } from '../utils/apiFetch'
import { SEV_ORDER, SEV_COLOR } from '../lib/severity'
import { downloadCsv } from '../lib/exportFindingsCsv'

const NS = 'pages.threatFeeds'
const columnHelper = createColumnHelper()
const WATCHLIST_TYPES = ['ipv4', 'domain', 'url', 'sha256', 'sha1', 'md5', 'email', 'cidr']

export default function ThreatFeeds() {
  const { t } = useTranslation()
  const [indicators, setIndicators] = useState([])
  const [feeds, setFeeds] = useState({ runs: [], stats: {}, enabled_feeds: [] })
  const [sightings, setSightings] = useState([])
  const [watchlist, setWatchlist] = useState([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState('')
  const [search, setSearch] = useState('')
  const [typeFilter, setTypeFilter] = useState('all')
  const [syncing, setSyncing] = useState(false)
  const [notice, setNotice] = useState('')
  const [wlType, setWlType] = useState('ipv4')
  const [wlValue, setWlValue] = useState('')

  const load = useCallback(async () => {
    setLoading(true)
    setError('')
    try {
      const [ind, fd, sg, wl] = await Promise.all([
        apiFetch('/api/ioc/indicators?limit=1000'),
        apiFetch('/api/ioc/feeds').catch(() => ({ runs: [], stats: {}, enabled_feeds: [] })),
        apiFetch('/api/ioc/sightings?limit=200').catch(() => ({ sightings: [] })),
        apiFetch('/api/ioc/watchlist').catch(() => ({ watchlist: [] })),
      ])
      if (ind?.ok === false) throw new Error(ind.detail || 'load failed')
      setIndicators(Array.isArray(ind.indicators) ? ind.indicators : [])
      setFeeds({
        runs: Array.isArray(fd?.runs) ? fd.runs : [],
        stats: fd?.stats || {},
        enabled_feeds: Array.isArray(fd?.enabled_feeds) ? fd.enabled_feeds : [],
      })
      setSightings(Array.isArray(sg?.sightings) ? sg.sightings : [])
      setWatchlist(Array.isArray(wl?.watchlist) ? wl.watchlist : [])
    } catch (e) {
      setError(e.message || t(`${NS}.load_failed`))
    } finally {
      setLoading(false)
    }
  }, [t])

  useEffect(() => {
    load()
  }, [load])

  const syncFeeds = useCallback(async () => {
    setSyncing(true)
    setNotice('')
    try {
      const d = await api.post('/api/ioc/ingest/run', {})
      setNotice(d?.message || t(`${NS}.sync_queued`))
    } catch (e) {
      setNotice(e.message || t(`${NS}.sync_failed`))
    } finally {
      setSyncing(false)
    }
  }, [t])

  const addWatch = useCallback(
    async (e) => {
      e.preventDefault()
      const value = wlValue.trim()
      if (!value) return
      try {
        await api.post('/api/ioc/watchlist', { type: wlType, value })
        setWlValue('')
        const wl = await apiFetch('/api/ioc/watchlist').catch(() => ({ watchlist: [] }))
        setWatchlist(Array.isArray(wl?.watchlist) ? wl.watchlist : [])
      } catch (err) {
        setNotice(err.message || t(`${NS}.watch_add_failed`))
      }
    },
    [wlType, wlValue, t],
  )

  const removeWatch = useCallback(
    async (id) => {
      try {
        await api.delete(`/api/ioc/watchlist/${id}`)
        setWatchlist((w) => w.filter((x) => x.id !== id))
      } catch (err) {
        setNotice(err.message || t(`${NS}.watch_del_failed`))
      }
    },
    [t],
  )

  const types = useMemo(
    () => [...new Set(indicators.map((i) => (i.type || '').toLowerCase()).filter(Boolean))].sort(),
    [indicators],
  )

  const filtered = useMemo(() => {
    const q = search.trim().toLowerCase()
    return indicators.filter((i) => {
      if (typeFilter !== 'all' && (i.type || '').toLowerCase() !== typeFilter) return false
      if (!q) return true
      return `${i.value} ${i.type} ${i.source} ${(i.tags || []).join(' ')}`.toLowerCase().includes(q)
    })
  }, [indicators, search, typeFilter])

  const stats = useMemo(() => {
    let critHigh = 0
    for (const i of indicators) {
      const s = (i.severity || '').toLowerCase()
      if (s === 'critical' || s === 'high') critHigh += 1
    }
    return {
      total: feeds?.stats?.total ?? indicators.length,
      feeds: feeds?.enabled_feeds?.length || 0,
      critHigh,
      sightings: sightings.length,
    }
  }, [indicators, feeds, sightings])

  const typePills = useMemo(
    () => [
      { id: 'all', label: t(`${NS}.all_types`), active: typeFilter === 'all', onClick: () => setTypeFilter('all') },
      ...types.map((ty) => ({ id: ty, label: ty, active: typeFilter === ty, onClick: () => setTypeFilter(ty) })),
    ],
    [types, typeFilter, t],
  )

  const exportCsv = useCallback(() => {
    const header = ['type', 'value', 'source', 'severity', 'confidence', 'effective_confidence', 'tlp', 'last_seen']
    const data = filtered.map((r) => [
      r.type, r.value, r.source, r.severity, r.confidence, r.effective_confidence, r.tlp, r.last_seen,
    ])
    downloadCsv(data, header, 'weissman-ioc-indicators')
  }, [filtered])

  const columns = useMemo(
    () => [
      columnHelper.accessor((i) => (i.type || '').toLowerCase(), {
        id: 'type',
        header: t(`${NS}.col_type`),
        cell: (ctx) => (
          <span className="text-[10px] font-mono px-2 py-0.5 rounded border border-violet-500/25 bg-violet-500/5 text-violet-300/80 uppercase">
            {ctx.getValue() || '—'}
          </span>
        ),
      }),
      columnHelper.accessor((i) => i.value || '', {
        id: 'value',
        header: t(`${NS}.col_value`),
        cell: (ctx) => (
          <span className="flex items-center gap-1.5 min-w-0">
            <code className="text-[12px] text-[var(--text-primary)] font-mono truncate max-w-[20rem]" title={ctx.getValue()}>
              {ctx.getValue() || '—'}
            </code>
            {ctx.getValue() && <CopyButton value={ctx.getValue()} />}
          </span>
        ),
      }),
      columnHelper.accessor((i) => i.source || '', {
        id: 'source',
        header: t(`${NS}.col_source`),
        cell: (ctx) => <span className="text-[var(--text-tertiary)] text-[11px] font-mono">{ctx.getValue() || '—'}</span>,
      }),
      columnHelper.accessor((i) => (i.severity || 'info').toLowerCase(), {
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
      columnHelper.accessor((i) => i.effective_confidence ?? i.confidence ?? 0, {
        id: 'confidence',
        header: t(`${NS}.col_confidence`),
        cell: (ctx) => {
          const eff = Number(ctx.getValue()) || 0
          const base = Number(ctx.row.original.confidence) || 0
          const c = eff >= 70 ? '#f43f5e' : eff >= 40 ? '#f59e0b' : '#64748b'
          return (
            <span className="flex items-center gap-2 min-w-[90px]" title={`base ${base} → effective ${eff} (decayed)`}>
              <span className="h-1.5 rounded-full" style={{ width: `${Math.max(6, eff)}%`, maxWidth: 60, background: c }} />
              <span className="text-[11px] font-mono text-[var(--text-tertiary)]">{eff}</span>
            </span>
          )
        },
      }),
      columnHelper.accessor((i) => (i.tlp || '').toUpperCase(), {
        id: 'tlp',
        header: t(`${NS}.col_tlp`),
        cell: (ctx) => <span className="text-[10px] font-mono text-[var(--text-muted)]">{ctx.getValue() || '—'}</span>,
      }),
      columnHelper.accessor((i) => i.last_seen || '', {
        id: 'last_seen',
        header: t(`${NS}.col_last_seen`),
        cell: (ctx) => (
          <span className="text-[var(--text-muted)] whitespace-nowrap text-[11px]">
            {ctx.getValue() ? new Date(ctx.getValue()).toLocaleString() : '—'}
          </span>
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
      badgeColor="#8b5cf6"
      icon={<Radar className="w-5 h-5" />}
      actions={
        <ShellScanActions
          onRefresh={load}
          onExport={exportCsv}
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
            <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
              <ExecutiveWidget label={t(`${NS}.kpi_total`)} value={stats.total} accent="#8b5cf6" />
              <ExecutiveWidget label={t(`${NS}.kpi_feeds`)} value={stats.feeds} accent="#22d3ee" />
              <ExecutiveWidget label={t(`${NS}.kpi_crit_high`)} value={stats.critHigh} accent="#f43f5e" />
              <ExecutiveWidget label={t(`${NS}.kpi_sightings`)} value={stats.sightings} accent="#f59e0b" />
            </div>

            {/* Feed health + sync */}
            <section className="rounded-xl border border-[var(--border-default)] bg-[var(--bg-2)] p-4">
              <div className="flex flex-wrap items-center justify-between gap-3 mb-3">
                <h3 className="text-sm font-semibold text-[var(--text-primary)]">{t(`${NS}.feeds_title`)}</h3>
                <button
                  type="button"
                  onClick={syncFeeds}
                  disabled={syncing}
                  className="inline-flex items-center gap-1.5 text-[12px] font-medium px-3 py-1.5 rounded-lg border border-violet-500/40 bg-violet-500/10 text-violet-200 hover:bg-violet-500/20 disabled:opacity-50"
                >
                  <RefreshCw className={`w-3.5 h-3.5 ${syncing ? 'animate-spin' : ''}`} />
                  {t(`${NS}.sync_feeds`)}
                </button>
              </div>
              {notice && <p className="text-[12px] text-cyan-300/80 font-mono mb-2">{notice}</p>}
              <div className="flex flex-wrap gap-2 mb-3">
                {feeds.enabled_feeds.length ? (
                  feeds.enabled_feeds.map((f) => (
                    <span key={f} className="text-[10px] font-mono px-2 py-0.5 rounded border border-emerald-500/25 bg-emerald-500/5 text-emerald-300/80">
                      {f}
                    </span>
                  ))
                ) : (
                  <span className="text-[11px] text-[var(--text-muted)]">{t(`${NS}.no_feeds_configured`)}</span>
                )}
              </div>
              {feeds.runs.length > 0 && (
                <ul className="text-[11px] font-mono text-[var(--text-tertiary)] space-y-1 max-h-40 overflow-y-auto">
                  {feeds.runs.slice(0, 8).map((r, idx) => (
                    <li key={idx} className="flex items-center gap-2">
                      <span className={r.status === 'ok' ? 'text-emerald-400' : r.status === 'error' ? 'text-rose-400' : 'text-amber-400'}>●</span>
                      <span className="w-20 truncate">{r.source}</span>
                      <span>{t(`${NS}.run_line`, { inserted: r.inserted, updated: r.updated })}</span>
                      <span className="text-[var(--text-muted)]">{r.started_at ? new Date(r.started_at).toLocaleString() : ''}</span>
                    </li>
                  ))}
                </ul>
              )}
            </section>

            {/* Watchlist */}
            <section className="rounded-xl border border-[var(--border-default)] bg-[var(--bg-2)] p-4">
              <h3 className="text-sm font-semibold text-[var(--text-primary)] mb-3">{t(`${NS}.watchlist_title`)}</h3>
              <form onSubmit={addWatch} className="flex flex-wrap items-center gap-2 mb-3">
                <select
                  value={wlType}
                  onChange={(e) => setWlType(e.target.value)}
                  aria-label={t(`${NS}.watch_type`)}
                  className="bg-[var(--bg-3)] border border-[var(--border-default)] rounded-lg px-2 py-1.5 text-[12px] text-[var(--text-primary)] font-mono"
                >
                  {WATCHLIST_TYPES.map((ty) => (
                    <option key={ty} value={ty}>{ty}</option>
                  ))}
                </select>
                <input
                  value={wlValue}
                  onChange={(e) => setWlValue(e.target.value)}
                  aria-label={t(`${NS}.watch_value`)}
                  placeholder={t(`${NS}.watch_placeholder`)}
                  className="flex-1 min-w-[200px] bg-[var(--bg-3)] border border-[var(--border-default)] rounded-lg px-3 py-1.5 text-[12px] text-[var(--text-primary)] font-mono focus:outline-none focus:border-violet-500/40"
                />
                <button type="submit" className="inline-flex items-center gap-1.5 text-[12px] font-medium px-3 py-1.5 rounded-lg border border-cyan-500/40 bg-cyan-500/10 text-cyan-200 hover:bg-cyan-500/20">
                  <Plus className="w-3.5 h-3.5" />
                  {t(`${NS}.watch_add`)}
                </button>
              </form>
              {watchlist.length === 0 ? (
                <p className="text-[11px] text-[var(--text-muted)]">{t(`${NS}.watch_empty`)}</p>
              ) : (
                <ul className="space-y-1 max-h-48 overflow-y-auto">
                  {watchlist.map((w) => (
                    <li key={w.id} className="flex items-center gap-2 text-[12px] font-mono">
                      <span className="text-[10px] px-1.5 py-0.5 rounded border border-violet-500/25 text-violet-300/80 uppercase">{w.type}</span>
                      <code className="text-[var(--text-primary)] truncate max-w-[18rem]" title={w.value}>{w.value}</code>
                      {w.note && <span className="text-[var(--text-muted)] truncate max-w-[12rem]">{w.note}</span>}
                      <button
                        type="button"
                        onClick={() => removeWatch(w.id)}
                        aria-label={t(`${NS}.watch_remove`)}
                        className="ml-auto text-rose-400/70 hover:text-rose-300"
                      >
                        <Trash2 className="w-3.5 h-3.5" />
                      </button>
                    </li>
                  ))}
                </ul>
              )}
            </section>

            {/* Indicator table */}
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
              {types.length > 0 && <FilterPills pills={typePills} />}
            </div>

            {indicators.length === 0 ? (
              <EmptyState icon="radar" title={t(`${NS}.empty_title`)} body={t(`${NS}.empty_body`)} />
            ) : filtered.length === 0 ? (
              <EmptyState icon="search-x" title={t(`${NS}.no_match_title`)} body={t(`${NS}.no_match_body`)} />
            ) : (
              <DataTable
                id="ioc-indicators-table"
                columns={columns}
                data={filtered}
                animateRows={false}
                getRowId={(i) => String(i.id)}
                getRowAccentColor={(i) => SEV_COLOR[(i.severity || 'info').toLowerCase()]}
              />
            )}
          </>
        )}
      </div>
    </PageShell>
  )
}
