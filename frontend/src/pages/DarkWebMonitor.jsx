/**
 * Dark Web Monitor — tenant-scoped intelligence from live `/api/findings` only.
 * Sources: leak_hunter, darkweb_intel, dark_web_monitor, typosquatting_monitor.
 */
import React, { useCallback, useEffect, useMemo, useState } from 'react'
import { Link } from 'react-router-dom'
import { useTranslation } from 'react-i18next'
import {
  Eye, RefreshCw, Search, Download, ShieldAlert, Radio, Filter,
} from 'lucide-react'
import PageShell from './PageShell'
import ShellScanActions from '../components/engine/ShellScanActions'
import { useFindingsWorkbench } from '../hooks/useFindingsWorkbench'
import EmptyState from '../components/ui/EmptyState'
import FindingDrawer from '../components/ui/FindingDrawer'
import { SkeletonTable, SkeletonWidgetGrid } from '../components/ui/Skeleton'
import { apiFetch } from '../lib/apiBase'

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
    info: 'text-slate-300 bg-slate-700/10 border-slate-500/40',
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
      const r = await apiFetch('/api/findings?limit=2000')
      if (!r.ok) throw new Error(`HTTP ${r.status}`)
      const d = await r.json()
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

  useEffect(() => {
    if (!autoRefresh) return undefined
    const id = setInterval(load, 60000)
    return () => clearInterval(id)
  }, [autoRefresh, load])

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

  return (
    <PageShell
      title={t('pages.darkWebMonitor.title')}
      subtitle={t('pages.darkWebMonitor.subtitle')}
      badge={t('pages.darkWebMonitor.badge')}
      badgeColor="#f43f5e"
      icon={<Eye />}
      actions={(
        <div className="flex items-center gap-2 flex-wrap">
          <button
            type="button"
            onClick={() => setAutoRefresh((v) => !v)}
            className={`px-3 py-1.5 rounded-lg border text-xs font-mono transition-colors ${
              autoRefresh
                ? 'border-emerald-500/40 text-emerald-300 bg-emerald-500/10'
                : 'border-white/10 text-white/50 hover:text-white/80'
            }`}
          >
            <Radio className={`w-3 h-3 inline mr-1 ${autoRefresh ? 'animate-pulse' : ''}`} />
            {autoRefresh ? t('pages.darkWebMonitor.auto_on') : t('pages.darkWebMonitor.auto_off')}
          </button>
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
          <p className="text-[10px] font-mono text-white/30">
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
              <KpiCard label={t('pages.darkWebMonitor.low_info')} value={stats.low + stats.info} accent="text-slate-300" />
            </div>

            {Object.keys(stats.bySource).length > 0 && (
              <div className="rounded-xl border border-white/10 bg-black/40 p-4">
                <h3 className="text-[10px] font-mono uppercase tracking-widest text-white/40 mb-3">
                  {t('pages.darkWebMonitor.source_breakdown')}
                </h3>
                <div className="space-y-2">
                  {Object.entries(stats.bySource)
                    .sort((a, b) => b[1] - a[1])
                    .map(([src, count]) => (
                      <div key={src} className="flex items-center gap-3">
                        <span className="text-xs font-mono text-white/60 w-40 truncate">{src}</span>
                        <div className="flex-1 h-2 bg-white/5 rounded-full overflow-hidden">
                          <div
                            className="h-full bg-rose-500/70 rounded-full"
                            style={{ width: `${stats.total ? (count / stats.total) * 100 : 0}%` }}
                          />
                        </div>
                        <span className="text-xs font-mono text-white/40 w-8 text-right">{count}</span>
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
            <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-white/30" />
            <input
              type="search"
              value={search}
              onChange={(e) => setSearch(e.target.value)}
              placeholder={t('pages.darkWebMonitor.search_placeholder')}
              className="w-full pl-10 pr-4 py-2 rounded-xl bg-black/40 border border-white/10 text-sm text-white placeholder-white/25 focus:outline-none focus:border-rose-500/40"
            />
          </div>
          <div className="flex items-center gap-1 bg-black/40 border border-white/10 rounded-lg p-1 flex-wrap">
            {['all', ...SEV_KEYS].map((s) => (
              <button
                key={s}
                type="button"
                onClick={() => setSeverityFilter(s)}
                className={`px-2.5 py-1 rounded-md text-[10px] font-mono uppercase transition-all ${
                  severityFilter === s
                    ? 'bg-rose-500/20 text-rose-300 border border-rose-500/30'
                    : 'text-white/45 hover:text-white/70'
                }`}
              >
                {s === 'all' ? t('pages.darkWebMonitor.filter_all') : s}
              </button>
            ))}
          </div>
          {sources.length > 1 && (
            <select
              value={sourceFilter}
              onChange={(e) => setSourceFilter(e.target.value)}
              className="px-3 py-2 rounded-lg bg-black/40 border border-white/10 text-xs text-white font-mono"
            >
              <option value="all">{t('pages.darkWebMonitor.all_sources')}</option>
              {sources.map((s) => (
                <option key={s} value={s}>{s}</option>
              ))}
            </select>
          )}
        </div>

        <section className="bg-black/40 border border-white/10 rounded-xl overflow-hidden">
          <div className="flex items-center justify-between p-4 border-b border-white/10">
            <h3 className="text-sm font-semibold text-white flex items-center gap-2">
              <Filter className="w-4 h-4 text-rose-400" />
              {t('pages.darkWebMonitor.findings_heading')}
              <span className="text-white/40 font-mono text-xs">({filtered.length})</span>
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
              <p className="text-xs text-white/40 text-center mt-4 max-w-lg mx-auto">
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
            <div className="overflow-x-auto">
              <table className="w-full text-[12px] font-mono">
                <thead>
                  <tr className="text-left text-white/45 border-b border-white/10">
                    <th className="py-2 px-4">{t('pages.darkWebMonitor.col_severity')}</th>
                    <th className="py-2 px-4">{t('pages.darkWebMonitor.col_title')}</th>
                    <th className="py-2 px-4">{t('pages.darkWebMonitor.col_source')}</th>
                    <th className="py-2 px-4">{t('pages.darkWebMonitor.col_target')}</th>
                    <th className="py-2 px-4">{t('pages.darkWebMonitor.col_discovered')}</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-white/5">
                  {filtered.slice(0, 200).map((f) => (
                    <tr
                      key={f.id || f.finding_id || f.title}
                      onClick={() => setSelected(f)}
                      className="hover:bg-white/[0.04] cursor-pointer transition-colors"
                    >
                      <td className="py-2 px-4">
                        <span className={severityBadgeClass(f.severity)}>{(f.severity || 'info').toUpperCase()}</span>
                      </td>
                      <td className="py-2 px-4 text-white/85 max-w-md truncate" title={f.title}>{f.title || '—'}</td>
                      <td className="py-2 px-4 text-white/55">{f.source || f.engine || '—'}</td>
                      <td className="py-2 px-4 text-white/55 max-w-xs truncate" title={f.target}>{f.target || '—'}</td>
                      <td className="py-2 px-4 text-white/40 whitespace-nowrap">
                        {f.discovered_at ? new Date(f.discovered_at).toLocaleString() : '—'}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
              {filtered.length > 200 && (
                <p className="text-center text-[10px] font-mono text-white/30 py-3">
                  {t('pages.darkWebMonitor.showing_first', { count: filtered.length })}
                </p>
              )}
            </div>
          )}
        </section>
      </div>

      <FindingDrawer finding={selected} onClose={() => setSelected(null)} />
    </PageShell>
  )
}

function KpiCard({ label, value, accent }) {
  return (
    <div className="rounded-2xl bg-black/40 border border-white/10 p-4">
      <div className="text-[10px] font-mono uppercase tracking-widest text-white/40">{label}</div>
      <div className={`text-3xl font-bold mt-1 ${accent || 'text-white'}`}>{value}</div>
    </div>
  )
}
