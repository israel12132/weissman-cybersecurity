import { useCallback, useEffect, useMemo, useState } from 'react'
import { useTranslation } from 'react-i18next'
import { ClipboardCheck, AlertTriangle, FileText, Search } from 'lucide-react'
import { useClient } from '../context/ClientContext'
import { apiFetch } from '../utils/apiFetch'
import { SkeletonTable } from '../components/ui/Skeleton'
import EmptyState from '../components/ui/EmptyState'
import EvidenceNotice from '../components/ui/EvidenceNotice'
import ShellScanActions from '../components/engine/ShellScanActions'
import Button from '../components/ui/Button'
import { exportRowsCsv, exportRowsPdf, rowMatchesQuery } from '../lib/pageExport'

/**
 * CompliancePosturePanel — live, client-scoped compliance-framework exposure.
 *
 * Renders GET /api/compliance/posture/:client_id: for each framework (OWASP / NIST / PCI …), the
 * controls a client's open findings touch, with per-control finding counts and severity. This is
 * the auditor's inverse of the remediation crosswalk — "where are we exposed, by control" —
 * computed server-side from the same CWE→control map, so the two views never disagree.
 */

const SEV_COLOR = { critical: '#f43f5e', high: '#fb923c', medium: '#fbbf24', low: '#38bdf8', info: '#94a3b8', other: '#64748b' }
const SEV_ORDER = ['critical', 'high', 'medium', 'low', 'info', 'other']

export const COMPLIANCE_CSV_HEADER = ['framework', 'control', 'title', 'finding_count', 'critical', 'high', 'medium', 'low', 'info', 'other']

/** Pure: flatten framework groups into one CSV row per control. Exported for tests. */
export function complianceCsvRows(frameworks) {
  if (!Array.isArray(frameworks)) return []
  const rows = []
  for (const g of frameworks) {
    const controls = Array.isArray(g?.controls) ? g.controls : []
    for (const c of controls) {
      rows.push([
        g?.framework ?? '',
        c?.control ?? '',
        c?.title ?? '',
        c?.finding_count ?? 0,
        c?.critical ?? 0,
        c?.high ?? 0,
        c?.medium ?? 0,
        c?.low ?? 0,
        c?.info ?? 0,
        c?.other ?? 0,
      ])
    }
  }
  return rows
}

function SeverityBar({ stat }) {
  const total = Number(stat?.finding_count) || 0
  if (!total) return null
  return (
    <div className="flex h-1.5 w-full max-w-[160px] rounded-full overflow-hidden bg-white/5">
      {SEV_ORDER.map((k) => {
        const v = Number(stat[k]) || 0
        if (!v) return null
        return <div key={k} style={{ width: `${(v / total) * 100}%`, background: SEV_COLOR[k] }} title={`${k}: ${v}`} />
      })}
    </div>
  )
}

export default function CompliancePosturePanel() {
  const { t } = useTranslation()
  const { selectedClientId, clients } = useClient()
  const clientId = useMemo(() => {
    if (selectedClientId != null && selectedClientId !== '') return selectedClientId
    const first = Array.isArray(clients) && clients.length ? Number(clients[0]?.id) : null
    return Number.isFinite(first) && first > 0 ? first : null
  }, [selectedClientId, clients])

  const [data, setData] = useState(null)
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState(null)
  const [searchQuery, setSearchQuery] = useState('')

  const load = useCallback(async (id) => {
    if (id == null) { setData(null); return }
    setLoading(true)
    setError(null)
    try {
      const d = await apiFetch(`/api/compliance/posture/${encodeURIComponent(id)}?limit=2000`)
      setData(d && typeof d === 'object' ? d : null)
    } catch (e) {
      setError(e?.message || 'load failed')
      setData(null)
    } finally {
      setLoading(false)
    }
  }, [])

  useEffect(() => { load(clientId) }, [clientId, load])

  const frameworks = useMemo(() => (Array.isArray(data?.frameworks) ? data.frameworks : []), [data])

  // Client-side filter over the already-loaded posture: keep only the control ROWS that match
  // the query (on control id, title, or framework name), and drop frameworks left with none.
  const filteredFrameworks = useMemo(() => {
    if (!searchQuery.trim()) return frameworks
    return frameworks
      .map((g) => {
        const controls = (Array.isArray(g?.controls) ? g.controls : []).filter((c) =>
          rowMatchesQuery(searchQuery, [c?.control, c?.title, g?.framework]),
        )
        return { ...g, controls }
      })
      .filter((g) => g.controls.length > 0)
  }, [frameworks, searchQuery])

  const handleRefresh = useCallback(() => load(clientId), [load, clientId])
  const exportCsv = useCallback(
    () => exportRowsCsv(COMPLIANCE_CSV_HEADER, complianceCsvRows(filteredFrameworks), 'weissman-compliance-posture'),
    [filteredFrameworks],
  )
  const exportPdf = useCallback(
    () =>
      exportRowsPdf(
        'Weissman Compliance Posture',
        COMPLIANCE_CSV_HEADER,
        complianceCsvRows(filteredFrameworks),
        'weissman-compliance-posture',
      ),
    [filteredFrameworks],
  )

  return (
    <div className="bg-black/40 backdrop-blur-md border border-white/10 rounded-xl overflow-hidden">
      <div className="px-4 pt-4">
        <EvidenceNotice>
          Live posture from GET /api/compliance/posture/:clientId — open findings crossed against the
          tenant-scoped CWE→control map. No fabricated control telemetry.
        </EvidenceNotice>
      </div>
      <div className="p-4 border-b border-white/10 flex items-center justify-between gap-3 flex-wrap">
        <h3 className="text-sm font-semibold text-white flex items-center gap-2">
          <ClipboardCheck className="w-4 h-4 text-emerald-400" />
          {t('pages.complianceFrameworks.posture_heading', { defaultValue: 'Live Compliance Exposure' })}
        </h3>
        <div className="flex items-center gap-3 flex-wrap">
          <div className="relative">
            <Search className="w-3 h-3 text-white/30 absolute left-2 top-1/2 -translate-y-1/2 pointer-events-none" />
            <input
              type="search"
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
              placeholder={t('common.search', { defaultValue: 'Search' })}
              aria-label={t('common.search', { defaultValue: 'Search controls' })}
              className="w-40 pl-6 pr-2 py-1 rounded-md text-[11px] bg-black/40 border border-white/10 text-white/80 placeholder-white/30 focus:outline-none focus:border-emerald-500/40"
            />
          </div>
          <ShellScanActions
            onRefresh={handleRefresh}
            onExport={exportCsv}
            refreshLoading={loading}
            exportDisabled={filteredFrameworks.length === 0}
          />
          <Button
            variant="unstyled"
            type="button"
            onClick={exportPdf}
            disabled={filteredFrameworks.length === 0}
            title={t('common.export_pdf', { defaultValue: 'Export PDF' })}
            className="inline-flex items-center gap-1.5 px-2.5 py-1.5 rounded-md text-[11px] font-semibold border border-white/15 text-white/70 hover:bg-white/10 disabled:opacity-40 transition-colors"
          >
            <FileText className="w-3.5 h-3.5" />
            {t('common.export_pdf', { defaultValue: 'PDF' })}
          </Button>
        </div>
      </div>

      {clientId == null ? (
        <div className="p-4"><EmptyState compact icon="shield" title={t('pages.complianceFrameworks.posture_no_client', { defaultValue: 'Select a client to load live compliance exposure.' })} /></div>
      ) : error ? (
        <div className="p-4 text-sm text-rose-300 flex items-center gap-2"><AlertTriangle className="w-4 h-4 shrink-0" />{t('pages.complianceFrameworks.posture_error', { error, defaultValue: "Couldn't load compliance exposure: {{error}}." })}</div>
      ) : loading ? (
        <div className="p-4"><SkeletonTable rows={5} cols={3} /></div>
      ) : frameworks.length === 0 ? (
        <div className="p-4"><EmptyState compact icon="shield" title={t('pages.complianceFrameworks.posture_empty', { defaultValue: 'No open findings map to a tracked control for this client.' })} /></div>
      ) : filteredFrameworks.length === 0 ? (
        <div className="p-4 text-[11px] text-white/35">{t('pages.complianceFrameworks.posture_no_match', { defaultValue: 'No controls matched this search.' })}</div>
      ) : (
        <div className="divide-y divide-white/5">
          {filteredFrameworks.map((g) => (
            <div key={g.framework} className="p-4">
              <div className="flex items-center justify-between mb-2">
                <span className="text-sm font-semibold text-emerald-300">{g.framework}</span>
                <span className="text-[10px] font-mono text-white/40 tabular-nums">
                  {t('pages.complianceFrameworks.posture_summary', {
                    controls: g.control_count,
                    findings: g.finding_count,
                    defaultValue: '{{controls}} controls · {{findings}} findings',
                  })}
                </span>
              </div>
              <div className="space-y-1.5">
                {(Array.isArray(g.controls) ? g.controls : []).map((c) => (
                  <div key={c.control} className="flex items-center gap-2">
                    <span className="w-24 shrink-0 text-[11px] font-mono text-white/70">{c.control}</span>
                    <span className="flex-1 min-w-0 text-[11px] text-white/50 truncate" title={c.title}>{c.title}</span>
                    <SeverityBar stat={c} />
                    <span className="w-8 shrink-0 text-right text-xs font-bold tabular-nums text-white">{c.finding_count}</span>
                  </div>
                ))}
              </div>
            </div>
          ))}
        </div>
      )}
    </div>
  )
}
