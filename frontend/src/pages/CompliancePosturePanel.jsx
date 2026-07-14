import { useCallback, useEffect, useMemo, useState } from 'react'
import { useTranslation } from 'react-i18next'
import { ClipboardCheck, Download, AlertTriangle } from 'lucide-react'
import { useClient } from '../context/ClientContext'
import { apiFetch } from '../lib/apiBase'
import { downloadCsv } from '../lib/exportFindingsCsv'
import { SkeletonTable } from '../components/ui/Skeleton'
import EmptyState from '../components/ui/EmptyState'

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

  const load = useCallback(async (id) => {
    if (id == null) { setData(null); return }
    setLoading(true)
    setError(null)
    try {
      const r = await apiFetch(`/api/compliance/posture/${encodeURIComponent(id)}?limit=2000`)
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

  useEffect(() => { load(clientId) }, [clientId, load])

  const frameworks = Array.isArray(data?.frameworks) ? data.frameworks : []

  return (
    <div className="bg-black/40 backdrop-blur-md border border-white/10 rounded-xl overflow-hidden">
      <div className="p-4 border-b border-white/10 flex items-center justify-between gap-3 flex-wrap">
        <h3 className="text-sm font-semibold text-white flex items-center gap-2">
          <ClipboardCheck className="w-4 h-4 text-emerald-400" />
          {t('pages.complianceFrameworks.posture_heading')}
        </h3>
        <button
          type="button"
          disabled={frameworks.length === 0}
          onClick={() => downloadCsv(complianceCsvRows(frameworks), COMPLIANCE_CSV_HEADER, 'weissman-compliance-posture')}
          className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded-md text-[11px] font-medium border border-emerald-500/30 text-emerald-300 hover:bg-emerald-500/10 disabled:opacity-40 disabled:cursor-not-allowed transition-colors"
        >
          <Download className="w-3.5 h-3.5" />
          {t('pages.complianceFrameworks.posture_export')}
        </button>
      </div>

      {clientId == null ? (
        <div className="p-4"><EmptyState compact icon="shield" title={t('pages.complianceFrameworks.posture_no_client')} /></div>
      ) : error ? (
        <div className="p-4 text-sm text-rose-300 flex items-center gap-2"><AlertTriangle className="w-4 h-4 shrink-0" />{t('pages.complianceFrameworks.posture_error', { error })}</div>
      ) : loading ? (
        <div className="p-4"><SkeletonTable rows={5} cols={3} /></div>
      ) : frameworks.length === 0 ? (
        <div className="p-4"><EmptyState compact icon="shield" title={t('pages.complianceFrameworks.posture_empty')} /></div>
      ) : (
        <div className="divide-y divide-white/5">
          {frameworks.map((g) => (
            <div key={g.framework} className="p-4">
              <div className="flex items-center justify-between mb-2">
                <span className="text-sm font-semibold text-emerald-300">{g.framework}</span>
                <span className="text-[10px] font-mono text-white/40 tabular-nums">
                  {t('pages.complianceFrameworks.posture_summary', {
                    controls: g.control_count,
                    findings: g.finding_count,
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
