import { useCallback, useEffect, useMemo, useState } from 'react'
import { useTranslation } from 'react-i18next'
import { Building2, AlertTriangle, FileText, Search } from 'lucide-react'
import { apiFetch } from '../lib/apiBase'
import { SkeletonWidgetGrid } from '../components/ui/Skeleton'
import EvidenceNotice from '../components/ui/EvidenceNotice'
import ShellScanActions from '../components/engine/ShellScanActions'
import { exportRowsCsv, exportRowsPdf, rowMatchesQuery } from '../lib/pageExport'

/** CSV/PDF columns for the worst-clients roll-up. Exported for tests. */
export const PORTFOLIO_CSV_HEADER = ['client_id', 'name', 'grade', 'score', 'kev_actions']

/** Pure: worst clients → export rows. Exported for tests. */
export function portfolioRows(worst) {
  return (Array.isArray(worst) ? worst : []).map((c) => [
    c?.client_id ?? '',
    c?.name ?? '',
    c?.grade ?? '',
    c?.score ?? 0,
    c?.kev_actions ?? 0,
  ])
}

/**
 * PortfolioPosturePanel — the MSSP / fleet-wide posture roll-up.
 *
 * Renders GET /api/portfolio/posture (tenant-scoped): the A–F grade distribution across all
 * clients, the fleet average score, clients-at-risk, and the worst offenders — so a security lead
 * running many clients sees where to look first without opening each one.
 */

const GRADE_COLOR = { A: '#34d399', B: '#a3e635', C: '#fbbf24', D: '#fb923c', F: '#f43f5e' }
const GRADES = ['A', 'B', 'C', 'D', 'F']

/** Pure: total clients across the grade distribution map; >=1 for a safe bar denominator. */
export function gradeTotal(distribution) {
  if (!distribution || typeof distribution !== 'object') return 1
  const sum = GRADES.reduce((acc, g) => acc + (Number(distribution[g]) || 0), 0)
  return Math.max(1, sum)
}

/** Pure: colour for an A–F grade. Exported for tests. */
export function gradeColor(grade) {
  return GRADE_COLOR[String(grade || '').toUpperCase()] || '#94a3b8'
}

export default function PortfolioPosturePanel() {
  const { t } = useTranslation()
  const [data, setData] = useState(null)
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState(null)
  const [searchQuery, setSearchQuery] = useState('')

  const load = useCallback(async () => {
    setLoading(true)
    setError(null)
    try {
      const r = await apiFetch('/api/portfolio/posture')
      if (!r.ok) throw new Error(`HTTP ${r.status}`)
      const d = await r.json()
      setData(d && typeof d === 'object' ? d : null)
    } catch (e) {
      setError(e?.message || 'load failed')
      setData(null)
    } finally {
      setLoading(false)
    }
  }, [])

  useEffect(() => { load() }, [load])

  // Worst offenders straight off the loaded roll-up (tenant-scoped) — no fabricated rows.
  const worst = useMemo(
    () => (Array.isArray(data?.worst_clients) ? data.worst_clients : []),
    [data],
  )

  // Client-side filter over the already-loaded worst list, matching on client name + grade.
  const filteredWorst = useMemo(
    () => worst.filter((c) => rowMatchesQuery(searchQuery, [c?.name, c?.grade])),
    [worst, searchQuery],
  )

  const handleRefresh = useCallback(() => load(), [load])
  const exportCsv = useCallback(
    () => exportRowsCsv(PORTFOLIO_CSV_HEADER, portfolioRows(filteredWorst), 'weissman-portfolio-posture'),
    [filteredWorst],
  )
  const exportPdf = useCallback(
    () =>
      exportRowsPdf('Weissman Portfolio Posture', PORTFOLIO_CSV_HEADER, portfolioRows(filteredWorst), 'weissman-portfolio-posture'),
    [filteredWorst],
  )

  if (loading) return <div className="mb-2"><SkeletonWidgetGrid count={4} /></div>
  if (error || !data || Number(data.client_count) === 0) return null

  const dist = data.grade_distribution || {}
  const total = gradeTotal(dist)
  const fleet = data.fleet || {}

  return (
    <div className="bg-black/40 backdrop-blur-md border border-white/10 rounded-xl overflow-hidden">
      <div className="px-4 pt-4">
        <EvidenceNotice>
          Live tenant-wide roll-up from GET /api/portfolio/posture — grade distribution and worst
          offenders computed across all clients. No fabricated posture telemetry.
        </EvidenceNotice>
      </div>
      <div className="p-4 border-b border-white/10 flex items-center justify-between gap-3 flex-wrap">
        <h3 className="text-sm font-semibold text-white flex items-center gap-2">
          <Building2 className="w-4 h-4 text-violet-400" />
          {t('clients_page.portfolio_heading', { defaultValue: 'Portfolio Posture' })}
        </h3>
        <div className="flex items-center gap-4 text-[11px] font-mono">
          <span className="text-white/60">
            {t('clients_page.portfolio_avg', { score: Number(data.average_score).toFixed(0), defaultValue: 'avg {{score}}' })}
          </span>
          {Number(data.clients_at_risk) > 0 && (
            <span className="inline-flex items-center gap-1 text-rose-300">
              <AlertTriangle className="w-3.5 h-3.5" />
              {t('clients_page.portfolio_at_risk', { count: data.clients_at_risk, defaultValue: '{{count}} at risk' })}
            </span>
          )}
          <ShellScanActions
            onRefresh={handleRefresh}
            onExport={exportCsv}
            refreshLoading={loading}
            exportDisabled={!filteredWorst.length}
          />
          <button
            type="button"
            onClick={exportPdf}
            disabled={!filteredWorst.length}
            title={t('common.export_pdf', { defaultValue: 'Export PDF' })}
            className="inline-flex items-center gap-1.5 px-2.5 py-1.5 rounded-md text-[11px] font-semibold border border-white/15 text-white/70 hover:bg-white/10 disabled:opacity-40 transition-colors"
          >
            <FileText className="w-3.5 h-3.5" />
            {t('common.export_pdf', { defaultValue: 'PDF' })}
          </button>
        </div>
      </div>

      <div className="p-4 grid grid-cols-1 md:grid-cols-[1fr,1fr] gap-6">
        {/* Grade distribution */}
        <div>
          <div className="text-[10px] uppercase tracking-wider text-white/40 mb-2">{t('clients_page.portfolio_grades', { defaultValue: 'Grade distribution' })}</div>
          <div className="space-y-1.5">
            {GRADES.map((g) => {
              const n = Number(dist[g]) || 0
              return (
                <div key={g} className="flex items-center gap-2">
                  <span className="w-4 text-xs font-bold" style={{ color: gradeColor(g) }}>{g}</span>
                  <div className="flex-1 h-2 rounded-full bg-white/5 overflow-hidden">
                    <div className="h-full rounded-full" style={{ width: `${(n / total) * 100}%`, background: gradeColor(g) }} />
                  </div>
                  <span className="w-6 text-right text-[11px] font-mono tabular-nums text-white/60">{n}</span>
                </div>
              )
            })}
          </div>
          <div className="mt-3 text-[10px] font-mono text-white/35">
            {t('clients_page.portfolio_fleet', {
              findings: Number(fleet.total_findings) || 0,
              kev: Number(fleet.kev_actions) || 0,
              overdue: Number(fleet.overdue_now) || 0,
              defaultValue: '{{findings}} findings · {{kev}} KEV · {{overdue}} overdue',
            })}
          </div>
        </div>

        {/* Worst clients */}
        <div>
          <div className="flex items-center justify-between gap-2 mb-2">
            <div className="text-[10px] uppercase tracking-wider text-white/40">{t('clients_page.portfolio_worst', { defaultValue: 'Needs attention first' })}</div>
            <div className="relative">
              <Search className="w-3 h-3 text-white/30 absolute left-2 top-1/2 -translate-y-1/2 pointer-events-none" />
              <input
                type="search"
                value={searchQuery}
                onChange={(e) => setSearchQuery(e.target.value)}
                placeholder={t('common.search', { defaultValue: 'Search' })}
                aria-label={t('common.search', { defaultValue: 'Search clients' })}
                className="w-32 pl-6 pr-2 py-1 rounded-md text-[11px] bg-black/40 border border-white/10 text-white/80 placeholder-white/30 focus:outline-none focus:border-violet-500/40"
              />
            </div>
          </div>
          <div className="space-y-1.5">
            {filteredWorst.length === 0 ? (
              <div className="text-[11px] text-white/35">{t('clients_page.portfolio_worst_none', { defaultValue: 'No clients matched.' })}</div>
            ) : filteredWorst.map((c) => (
              <div key={c.client_id} className="flex items-center gap-2">
                <span className="text-sm font-black w-5 shrink-0" style={{ color: gradeColor(c.grade) }}>{c.grade}</span>
                <span className="flex-1 min-w-0 text-[12px] text-white/80 truncate" title={c.name}>{c.name || `#${c.client_id}`}</span>
                {Number(c.kev_actions) > 0 && (
                  <span className="text-[10px] font-mono text-orange-300">{t('clients_page.portfolio_kev', { count: c.kev_actions, defaultValue: '{{count}} KEV' })}</span>
                )}
                <span className="text-[12px] font-bold tabular-nums w-8 text-right" style={{ color: gradeColor(c.grade) }}>{Number(c.score).toFixed(0)}</span>
              </div>
            ))}
          </div>
        </div>
      </div>
    </div>
  )
}
