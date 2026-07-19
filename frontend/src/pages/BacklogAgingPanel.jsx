import { useCallback, useEffect, useMemo, useState } from 'react'
import { useTranslation } from 'react-i18next'
import { Hourglass, AlertTriangle, FileText } from 'lucide-react'
import { useClient } from '../context/ClientContext'
import { apiFetch } from '../lib/apiBase'
import EvidenceNotice from '../components/ui/EvidenceNotice'
import ShellScanActions from '../components/engine/ShellScanActions'
import { exportRowsCsv, exportRowsPdf } from '../lib/pageExport'
import Button from '../components/ui/Button'

/** CSV/PDF columns for the age-bucket backlog. Exported for tests. */
export const BACKLOG_AGING_CSV_HEADER = ['label', 'total', 'critical', 'high', 'medium', 'low']

/** Pure: age buckets → export rows. Exported for tests. */
export function backlogAgingRows(buckets) {
  return (Array.isArray(buckets) ? buckets : []).map((b) => [
    b?.label ?? '',
    b?.total ?? 0,
    b?.critical ?? 0,
    b?.high ?? 0,
    b?.medium ?? 0,
    b?.low ?? 0,
  ])
}

/**
 * BacklogAgingPanel — how stale is the client's open-finding backlog?
 *
 * Renders GET /api/remediation/aging/:client_id: open findings bucketed by age (0-7 … 180d+) with
 * a per-bucket severity breakdown, plus red-flag counts for criticals/highs left open > 90 days.
 * Complements the SLA views (deadlines) with plain backlog health (raw age).
 */

const SEV_COLOR = { critical: '#f43f5e', high: '#fb923c', medium: '#fbbf24', low: '#38bdf8', info: '#94a3b8', other: '#64748b' }
const SEV_ORDER = ['critical', 'high', 'medium', 'low', 'info', 'other']

/** Pure: largest bucket total (for bar scaling); >=1 to avoid a zero denominator. */
export function maxBucketTotal(buckets) {
  if (!Array.isArray(buckets) || buckets.length === 0) return 1
  return Math.max(1, ...buckets.map((b) => Number(b?.total) || 0))
}

function SeverityBar({ bucket, width }) {
  const total = Number(bucket?.total) || 0
  return (
    <div className="h-3 rounded bg-white/5 overflow-hidden" style={{ width: `${width}%`, minWidth: total ? '4px' : '0' }}>
      <div className="flex h-full w-full">
        {SEV_ORDER.map((k) => {
          const v = Number(bucket[k]) || 0
          if (!v || !total) return null
          return <div key={k} style={{ width: `${(v / total) * 100}%`, background: SEV_COLOR[k] }} title={`${k}: ${v}`} />
        })}
      </div>
    </div>
  )
}

export default function BacklogAgingPanel() {
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
      const r = await apiFetch(`/api/remediation/aging/${encodeURIComponent(id)}?limit=2000`)
      if (!r.ok) throw new Error(`HTTP ${r.status}`)
      const d = await r.json()
      setData(d?.aging && typeof d.aging === 'object' ? d.aging : null)
    } catch (e) {
      setError(e?.message || 'load failed')
      setData(null)
    } finally {
      setLoading(false)
    }
  }, [])

  useEffect(() => { load(clientId) }, [clientId, load])

  const buckets = useMemo(() => (Array.isArray(data?.buckets) ? data.buckets : []), [data])
  const barMax = maxBucketTotal(buckets)
  const hasFindings = buckets.some((b) => (Number(b.total) || 0) > 0)

  const handleRefresh = useCallback(() => load(clientId), [load, clientId])
  const exportCsv = useCallback(
    () => exportRowsCsv(BACKLOG_AGING_CSV_HEADER, backlogAgingRows(buckets), 'weissman-backlog-aging'),
    [buckets],
  )
  const exportPdf = useCallback(
    () => exportRowsPdf('Weissman Backlog Aging', BACKLOG_AGING_CSV_HEADER, backlogAgingRows(buckets), 'weissman-backlog-aging'),
    [buckets],
  )

  if (clientId == null || loading || error || !hasFindings) return null

  const agedCriticals = Number(data?.aged_criticals) || 0
  const agedHighs = Number(data?.aged_highs) || 0

  return (
    <div className="bg-black/40 backdrop-blur-md border border-white/10 rounded-xl overflow-hidden">
      <div className="px-4 pt-4">
        <EvidenceNotice>
          Live backlog from GET /api/remediation/aging/:clientId — open findings bucketed by age
          from the tenant-scoped remediation store. No fabricated aging telemetry.
        </EvidenceNotice>
      </div>
      <div className="p-4 border-b border-white/10 flex items-center justify-between gap-3 flex-wrap">
        <h3 className="text-sm font-semibold text-white flex items-center gap-2">
          <Hourglass className="w-4 h-4 text-amber-400" />
          {t('pages.remediationHub.aging_heading')}
        </h3>
        <div className="flex items-center gap-3">
          {(agedCriticals > 0 || agedHighs > 0) && (
            <span className="inline-flex items-center gap-1 text-[11px] text-rose-300 font-medium">
              <AlertTriangle className="w-3.5 h-3.5" />
              {t('pages.remediationHub.aging_aged', {
                criticals: agedCriticals,
                highs: agedHighs,
              })}
            </span>
          )}
          <ShellScanActions
            onRefresh={handleRefresh}
            onExport={exportCsv}
            refreshLoading={loading}
            exportDisabled={!buckets.length}
          />
          <Button
            variant="unstyled"
            type="button"
            onClick={exportPdf}
            disabled={!buckets.length}
            title={t('common.export_pdf')}
            className="inline-flex items-center gap-1.5 px-2.5 py-1.5 rounded-md text-[11px] font-semibold border border-white/15 text-white/70 hover:bg-white/10 disabled:opacity-40 transition-colors"
          >
            <FileText className="w-3.5 h-3.5" />
            {t('common.export_pdf')}
          </Button>
        </div>
      </div>

      <div className="p-4 space-y-2">
        {buckets.map((b) => (
          <div key={b.label} className="flex items-center gap-3">
            <div className="w-16 shrink-0 text-[11px] font-mono text-white/50">{b.label}</div>
            <div className="flex-1">
              <SeverityBar bucket={b} width={((Number(b.total) || 0) / barMax) * 100} />
            </div>
            <div className="w-8 shrink-0 text-right text-xs font-bold tabular-nums text-white">{b.total}</div>
          </div>
        ))}
        {Number(data?.unknown_age) > 0 && (
          <div className="text-[10px] text-white/35 font-mono pt-1">
            {t('pages.remediationHub.aging_unknown', { count: data.unknown_age })}
          </div>
        )}
      </div>
    </div>
  )
}
