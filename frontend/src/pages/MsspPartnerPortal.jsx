/**
 * MSSP Partner Portal — live fleet posture (GET /api/portfolio/posture).
 * Not the AdvancedShowcase Acme demo.
 */
import { useCallback, useEffect, useMemo, useState } from 'react'
import { useTranslation } from 'react-i18next'
import { Building2, Search } from 'lucide-react'
import PageShell from './PageShell'
import EmptyState from '../components/ui/EmptyState'
import EvidenceNotice from '../components/ui/EvidenceNotice'
import ExecutiveWidget from '../components/ui/ExecutiveWidget'
import ShellScanActions from '../components/engine/ShellScanActions'
import { SkeletonWidgetGrid } from '../components/ui/Skeleton'
import { apiFetch } from '../utils/apiFetch'
import { downloadCsv } from '../lib/exportFindingsCsv'
import { portfolioRows, PORTFOLIO_CSV_HEADER, gradeColor, gradeTotal } from './PortfolioPosturePanel'

const NS = 'pages.msspPartnerPortal'
const GRADES = ['A', 'B', 'C', 'D', 'F']

export default function MsspPartnerPortal() {
  const { t } = useTranslation()
  const [data, setData] = useState(null)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState('')
  const [searchQuery, setSearchQuery] = useState('')

  const load = useCallback(async () => {
    setLoading(true)
    setError('')
    try {
      const d = await apiFetch('/api/portfolio/posture')
      if (d?.ok === false) throw new Error(d.detail || 'load failed')
      setData(d && typeof d === 'object' ? d : null)
    } catch (e) {
      setError(e.message || t(`${NS}.load_failed`))
      setData(null)
    } finally {
      setLoading(false)
    }
  }, [t])

  useEffect(() => { load() }, [load])

  const worst = useMemo(
    () => (Array.isArray(data?.worst_clients) ? data.worst_clients : []),
    [data],
  )
  const filtered = useMemo(() => {
    const q = searchQuery.trim().toLowerCase()
    if (!q) return worst
    return worst.filter((c) => `${c?.name || ''} ${c?.grade || ''}`.toLowerCase().includes(q))
  }, [worst, searchQuery])

  const exportCsv = useCallback(
    () => downloadCsv(portfolioRows(filtered), PORTFOLIO_CSV_HEADER, 'weissman-mssp-portfolio'),
    [filtered],
  )

  const dist = data?.grade_distribution || {}
  const fleet = data?.fleet || {}

  return (
    <PageShell
      title={t(`${NS}.title`)}
      subtitle={t(`${NS}.subtitle`)}
      icon={<Building2 />}
      actions={(
        <ShellScanActions
          onRefresh={load}
          onExport={exportCsv}
          refreshLoading={loading}
          exportDisabled={!filtered.length}
        />
      )}
    >
      <EvidenceNotice>{t(`${NS}.evidence_notice`)}</EvidenceNotice>
      {loading ? (
        <SkeletonWidgetGrid count={4} />
      ) : error ? (
        <EmptyState title={t(`${NS}.load_failed`)} body={error} />
      ) : (
        <div className="space-y-6">
          <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
            <ExecutiveWidget label={t(`${NS}.kpi_clients`)} value={Number(data?.client_count) || 0} />
            <ExecutiveWidget label={t(`${NS}.kpi_avg`)} value={Number(data?.average_score || 0).toFixed(0)} />
            <ExecutiveWidget label={t(`${NS}.kpi_risk`)} value={Number(data?.clients_at_risk) || 0} />
            <ExecutiveWidget label={t(`${NS}.kpi_kev`)} value={Number(fleet.kev_actions) || 0} />
          </div>
          <div className="relative max-w-sm">
            <Search className="w-3.5 h-3.5 text-white/30 absolute left-2.5 top-1/2 -translate-y-1/2" />
            <input
              type="search"
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
              placeholder={t(`${NS}.search_placeholder`)}
              aria-label={t(`${NS}.search_placeholder`)}
              className="w-full pl-8 pr-3 py-2 rounded-lg text-sm bg-black/40 border border-white/10 text-white"
            />
          </div>
          {!filtered.length ? (
            <EmptyState title={t(`${NS}.empty_title`)} body={t(`${NS}.empty_body`)} />
          ) : (
            <div className="grid md:grid-cols-2 gap-6">
              <div className="space-y-1.5">
                {GRADES.map((g) => {
                  const n = Number(dist[g]) || 0
                  const total = gradeTotal(dist)
                  return (
                    <div key={g} className="flex items-center gap-2">
                      <span className="w-4 text-xs font-bold" style={{ color: gradeColor(g) }}>{g}</span>
                      <div className="flex-1 h-2 rounded-full bg-white/5 overflow-hidden">
                        <div className="h-full" style={{ width: `${(n / total) * 100}%`, background: gradeColor(g) }} />
                      </div>
                      <span className="w-6 text-right text-[11px] font-mono text-white/60">{n}</span>
                    </div>
                  )
                })}
              </div>
              <ul className="space-y-2">
                {filtered.map((c) => (
                  <li key={c.client_id} className="flex justify-between text-sm border border-white/10 rounded-lg px-3 py-2">
                    <span className="truncate">{c.name || c.client_id}</span>
                    <span className="font-mono" style={{ color: gradeColor(c.grade) }}>{c.grade} · {c.score}</span>
                  </li>
                ))}
              </ul>
            </div>
          )}
        </div>
      )}
    </PageShell>
  )
}
