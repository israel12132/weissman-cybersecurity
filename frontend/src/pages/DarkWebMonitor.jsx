/**
 * Dark Web Monitor — tenant-scoped intelligence from live `/api/findings` only.
 * Sources: leak_hunter, darkweb_intel, dark_web_monitor, typosquatting_monitor.
 */
import { useCallback, useEffect, useMemo, useState } from 'react'
import { Link } from 'react-router-dom'
import { useTranslation } from 'react-i18next'
import { Eye, Search, ShieldAlert, Radio, Filter } from 'lucide-react'
import { createColumnHelper } from '@tanstack/react-table'
import PageShell from './PageShell'
import ShellScanActions from '../components/engine/ShellScanActions'
import { useFindingsWorkbench } from '../hooks/useFindingsWorkbench'
import EmptyState from '../components/ui/EmptyState'
import DataTable from '../components/ui/DataTable'
import FindingDrawer from '../components/ui/FindingDrawer'
import { SkeletonTable, SkeletonWidgetGrid } from '../components/ui/Skeleton'
import { apiFetch } from '../utils/apiFetch'
import { useVisiblePolling } from '../hooks/useVisiblePolling'
import Button from '../components/ui/Button'

const columnHelper = createColumnHelper()

const SEVERITY_ORDER = { critical: 4, high: 3, medium: 2, low: 1, info: 0 }
const DARK_WEB_SOURCES = new Set([
  'leak_hunter',
  'darkweb_intel',
  'dark_web_monitor',
  'typosquatting_monitor',
])
const SEV_KEYS = ['critical', 'high', 'medium', 'low', 'info']

function severityBadgeClass(sev) {
  const s = (sev || 'info').toLowerCase()
  const map = {
    critical: 'text-rose-300 bg-rose-500/10 border-rose-500/40',
    high: 'text-orange-300 bg-orange-500/10 border-orange-500/40',
    medium: 'text-yellow-300 bg-yellow-500/10 border-yellow-500/40',
    low: 'text-blue-300 bg-blue-500/10 border-blue-500/40',
    info: 'text-[var(--text-secondary)] bg-[var(--bg-4)]/10 border-[var(--border-strong)]/40',
  }
  return `inline-block px-2 py-0.5 rounded text-[10px] font-mono uppercase tracking-wider border ${map[s] || map.info}`
}

function parseFindings(data) {
  const arr = Array.isArray(data) ? data : Array.isArray(data?.findings) ? data.findings : []
  return arr
    .filter((f) => DARK_WEB_SOURCES.has((f.source || f.engine || '').toLowerCase()))
    .sort(
      (a, b) =>
        (SEVERITY_ORDER[(b.severity || '').toLowerCase()] || 0)
        - (SEVERITY_ORDER[(a.severity || '').toLowerCase()] || 0),
    )
}

export default function DarkWebMonitor() {
  const { t } = useTranslation()
  const [findings, setFindings] = useState([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState(null)
  const [search, setSearch] = useState('')
  const [severityFilter, setSeverityFilter] = useState('all')
  const [sourceFilter, setSourceFilter] = useState('all')
  const [selected, setSelected] = useState(null)
  const [lastRefresh, setLastRefresh] = useState(null)
  const [autoRefresh, setAutoRefresh] = useState(false)

  const load = useCallback(async () => {
    setError(null)
    try {
      const d = await apiFetch('/api/findings?limit=2000')
      setFindings(parseFindings(d))
      setLastRefresh(new Date())
    } catch (e) {
      setError(e.message || t('pages.darkWebMonitor.load_error', { error: '' }))
      setFindings([])
    } finally {
      setLoading(false)
    }
  }, [t])

  useEffect(() => {
    load()
  }, [load])

  // Auto-refresh every 60s, skipping ticks while the tab is hidden.
  useVisiblePolling(load, 60000, { paused: !autoRefresh })

  const sources = useMemo(
    () => [...new Set(findings.map((f) => (f.source || f.engine || '').toLowerCase()).filter(Boolean))].sort(),
    [findings],
  )

  const filtered = useMemo(() => {
    const q = search.trim().toLowerCase()
    return findings.filter((f) => {
      const sev = (f.severity || 'info').toLowerCase()
      const src = (f.source || f.engine || '').toLowerCase()
      if (severityFilter !== 'all' && sev !== severityFilter) return false
      if (sourceFilter !== 'all' && src !== sourceFilter) return false
      if (!q) return true
      const hay = `${f.title || ''} ${f.description || ''} ${f.target || ''} ${src}`.toLowerCase()
      return hay.includes(q)
    })
  }, [findings, search, severityFilter, sourceFilter])

  const stats = useMemo(() => {
    const by = Object.fromEntries(SEV_KEYS.map((k) => [k, 0]))
    const bySource = {}
    for (const f of findings) {
      const s = (f.severity || 'info').toLowerCase()
      if (by[s] !== undefined) by[s] += 1
      const src = (f.source || f.engine || 'unknown').toLowerCase()
      bySource[src] = (bySource[src] || 0) + 1
    }
    return { ...by, total: findings.length, bySource }
  }, [findings])

  const { exportCsv: exportWorkbenchCsv } = useFindingsWorkbench(filtered, { csvPrefix: 'dark-web-findings' })

  const exportCsv = () => {
    if (filtered.length) exportWorkbenchCsv()
  }

  const columns = useMemo(
    () => [
      columnHelper.accessor((f) => (f.severity || 'info').toLowerCase(), {
        id: 'severity',
        header: t('pages.darkWebMonitor.col_severity'),
        cell: (ctx) => (
          <span className={severityBadgeClass(ctx.getValue())}>{String(ctx.getValue()).toUpperCase()}</span>
        ),
        sortingFn: (a, b) =>
          (SEVERITY_ORDER[a.getValue('severity')] || 0) - (SEVERITY_ORDER[b.getValue('severity')] || 0),
      }),
      columnHelper.accessor((f) => f.title || '', {
        id: 'title',
        header: t('pages.darkWebMonitor.col_title'),
        cell: (ctx) => (
          <span className="text-[var(--text-primary)] max-w-md truncate block" title={ctx.getValue()}>
            {ctx.getValue() || '—'}
          </span>
        ),
      }),
      columnHelper.accessor((f) => f.source || f.engine || '', {
        id: 'source',
        header: t('pages.darkWebMonitor.col_source'),
        cell: (ctx) => <span className="text-[var(--text-tertiary)]">{ctx.getValue() || '—'}</span>,
      }),
      columnHelper.accessor((f) => f.target || '', {
        id: 'target',
        header: t('pages.darkWebMonitor.col_target'),
        cell: (ctx) => (
          <span className="text-[var(--text-tertiary)] max-w-xs truncate block" title={ctx.getValue()}>
            {ctx.getValue() || '—'}
          </span>
        ),
      }),
      columnHelper.accessor((f) => f.discovered_at || '', {
        id: 'discovered',
        header: t('pages.darkWebMonitor.col_discovered'),
        cell: (ctx) => (
          <span className="text-[var(--text-muted)] whitespace-nowrap">
            {ctx.getValue() ? new Date(ctx.getValue()).toLocaleString() : '—'}
          </span>
        ),
      }),
    ],
    [t],
  )

  return (
    <PageShell
      title={t('pages.darkWebMonitor.title')}
      subtitle={t('pages.darkWebMonitor.subtitle')}
      badge={t('pages.darkWebMonitor.badge')}
      badgeColor="#f43f5e"
      icon={<Eye />}
      actions={(
        <div className="flex items-center gap-2 flex-wrap">
          <Button variant="unstyled"
            type="button"
            onClick={() => setAutoRefresh((v) => !v)}
            className={`px-3 py-1.5 rounded-lg border text-xs font-mono transition-colors ${
              autoRefresh
                ? 'border-emerald-500/40 text-emerald-300 bg-emerald-500/10'
                : 'border-[var(--border-default)] text-[var(--text-tertiary)] hover:text-[var(--text-secondary)]'
            }`}
          >
            <Radio className={`w-3 h-3 inline mr-1 ${autoRefresh ? 'animate-pulse' : ''}`} />
            {autoRefresh ? t('pages.darkWebMonitor.auto_on') : t('pages.darkWebMonitor.auto_off')}
          </Button>
          <ShellScanActions
            onRefresh={load}
            onExport={exportCsv}
            refreshLoading={loading}
            exportDisabled={filtered.length === 0}
          />
        </div>
      )}
    >
      <div className="space-y-6">
        <div className="rounded-xl border border-rose-500/20 bg-rose-950/20 px-4 py-3 flex items-start gap-3">
          <ShieldAlert className="w-4 h-4 text-rose-400 mt-0.5 shrink-0" />
          <p className="text-xs text-rose-100/70 leading-relaxed">{t('pages.darkWebMonitor.evidence_notice')}</p>
        </div>

        {lastRefresh && (
          <p className="text-[10px] font-mono text-[var(--text-disabled)]">
            {t('pages.darkWebMonitor.last_updated', { time: lastRefresh.toLocaleTimeString() })}
          </p>
        )}

        {loading && findings.length === 0 ? (
          <SkeletonWidgetGrid count={5} />
        ) : (
          <>
            <div className="grid grid-cols-2 md:grid-cols-5 gap-4">
              <KpiCard label={t('pages.darkWebMonitor.total_hits')} value={stats.total} />
              <KpiCard label={t('pages.darkWebMonitor.critical')} value={stats.critical} accent="text-rose-300" />
              <KpiCard label={t('pages.darkWebMonitor.high')} value={stats.high} accent="text-orange-300" />
              <KpiCard label={t('pages.darkWebMonitor.medium')} value={stats.medium} accent="text-yellow-300" />
              <KpiCard label={t('pages.darkWebMonitor.low_info')} value={stats.low + stats.info} accent="text-[var(--text-secondary)]" />
            </div>

            {Object.keys(stats.bySource).length > 0 && (
              <div className="rounded-xl border border-[var(--border-default)] bg-[var(--bg-2)] p-4">
                <h3 className="text-[10px] font-mono uppercase tracking-widest text-[var(--text-muted)] mb-3">
                  {t('pages.darkWebMonitor.source_breakdown')}
                </h3>
                <div className="space-y-2">
                  {Object.entries(stats.bySource)
                    .sort((a, b) => b[1] - a[1])
                    .map(([src, count]) => (
                      <div key={src} className="flex items-center gap-3">
                        <span className="text-xs font-mono text-[var(--text-tertiary)] w-40 truncate">{src}</span>
                        <div className="flex-1 h-2 bg-[var(--row-hover-bg)] rounded-full overflow-hidden">
                          <div
                            className="h-full bg-rose-500/70 rounded-full"
                            style={{ width: `${stats.total ? (count / stats.total) * 100 : 0}%` }}
                          />
                        </div>
                        <span className="text-xs font-mono text-[var(--text-muted)] w-8 text-right">{count}</span>
                      </div>
                    ))}
                </div>
              </div>
            )}
          </>
        )}

        {error && (
          <div className="p-4 rounded-xl border border-red-500/30 bg-red-900/20 text-red-300 text-sm">
            {t('pages.darkWebMonitor.load_error', { error })}
          </div>
        )}

        <div className="flex flex-wrap items-center gap-3">
          <div className="relative flex-1 min-w-[200px]">
            <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-[var(--text-disabled)]" />
            <input
              type="search"
              value={search}
              onChange={(e) => setSearch(e.target.value)}
              aria-label={t('pages.darkWebMonitor.search_placeholder')}
              placeholder={t('pages.darkWebMonitor.search_placeholder')}
              className="w-full pl-10 pr-4 py-2 rounded-xl bg-[var(--bg-2)] border border-[var(--border-default)] text-sm text-white placeholder-white/25 focus:outline-none focus:border-rose-500/40"
            />
          </div>
          <div className="flex items-center gap-1 bg-[var(--bg-2)] border border-[var(--border-default)] rounded-lg p-1 flex-wrap">
            {['all', ...SEV_KEYS].map((s) => (
              <Button variant="unstyled"
                key={s}
                type="button"
                onClick={() => setSeverityFilter(s)}
                className={`px-2.5 py-1 rounded-md text-[10px] font-mono uppercase transition-all ${
                  severityFilter === s
                    ? 'bg-rose-500/20 text-rose-300 border border-rose-500/30'
                    : 'text-[var(--text-muted)] hover:text-[var(--text-secondary)]'
                }`}
              >
                {s === 'all' ? t('pages.darkWebMonitor.filter_all') : s}
              </Button>
            ))}
          </div>
          {sources.length > 1 && (
            <select
              value={sourceFilter}
              onChange={(e) => setSourceFilter(e.target.value)}
              className="px-3 py-2 rounded-lg bg-[var(--bg-2)] border border-[var(--border-default)] text-xs text-white font-mono"
            >
              <option value="all">{t('pages.darkWebMonitor.all_sources')}</option>
              {sources.map((s) => (
                <option key={s} value={s}>{s}</option>
              ))}
            </select>
          )}
        </div>

        <section className="bg-[var(--bg-2)] border border-[var(--border-default)] rounded-xl overflow-hidden">
          <div className="flex items-center justify-between p-4 border-b border-[var(--border-default)]">
            <h3 className="text-sm font-semibold text-white flex items-center gap-2">
              <Filter className="w-4 h-4 text-rose-400" />
              {t('pages.darkWebMonitor.findings_heading')}
              <span className="text-[var(--text-muted)] font-mono text-xs">({filtered.length})</span>
            </h3>
            <Link to="/findings" className="text-xs text-cyan-300 hover:text-cyan-200">
              {t('pages.darkWebMonitor.open_findings')}
            </Link>
          </div>

          {loading && findings.length === 0 ? (
            <div className="p-6"><SkeletonTable rows={6} cols={5} /></div>
          ) : findings.length === 0 ? (
            <div className="p-8">
              <EmptyState
                icon="radar"
                title={t('pages.darkWebMonitor.empty_title')}
                body={t('pages.darkWebMonitor.empty_body')}
                cta={{ label: t('pages.darkWebMonitor.empty_step_scan_link'), to: '/clients' }}
                secondary={{ label: t('pages.darkWebMonitor.empty_step_engine_link'), to: '/engines' }}
              />
              <p className="text-xs text-[var(--text-muted)] text-center mt-4 max-w-lg mx-auto">
                {t('pages.darkWebMonitor.empty_step_keys')}
              </p>
            </div>
          ) : filtered.length === 0 ? (
            <div className="p-8">
              <EmptyState
                icon="search-x"
                title={t('pages.darkWebMonitor.no_filter_title')}
                body={t('pages.darkWebMonitor.no_filter_body')}
              />
            </div>
          ) : (
            <DataTable
              id="darkweb-table"
              columns={columns}
              data={filtered}
              onRowClick={(row) => setSelected(row.original)}
              getRowId={(f) => f.id || f.finding_id || f.title}
              selectedRowId={selected ? selected.id || selected.finding_id || selected.title : null}
              getRowAccentColor={(f) => {
                const s = (f.severity || 'info').toLowerCase()
                return s === 'critical' ? '#f43f5e' : s === 'high' ? '#f97316' : undefined
              }}
              animateRows={false}
            />
          )}
        </section>
      </div>

      <FindingDrawer finding={selected} onClose={() => setSelected(null)} />
    </PageShell>
  )
}

function KpiCard({ label, value, accent }) {
  return (
    <div className="rounded-2xl bg-[var(--bg-2)] border border-[var(--border-default)] p-4">
      <div className="text-[10px] font-mono uppercase tracking-widest text-[var(--text-muted)]">{label}</div>
      <div className={`text-3xl font-bold mt-1 ${accent || 'text-white'}`}>{value}</div>
    </div>
  )
}
