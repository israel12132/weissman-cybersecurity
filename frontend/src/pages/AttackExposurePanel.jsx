import { useCallback, useEffect, useMemo, useState } from 'react'
import { useTranslation } from 'react-i18next'
import { Crosshair, AlertTriangle, FileText, Search } from 'lucide-react'
import { apiFetch } from '../lib/apiBase'
import { downloadCsv } from '../lib/exportFindingsCsv'
import { SkeletonTable } from '../components/ui/Skeleton'
import EmptyState from '../components/ui/EmptyState'
import EvidenceNotice from '../components/ui/EvidenceNotice'
import ShellScanActions from '../components/engine/ShellScanActions'
import Button from '../components/ui/Button'
import { exportRowsPdf, rowMatchesQuery } from '../lib/pageExport'

/**
 * AttackExposurePanel — live MITRE ATT&CK exposure for one client.
 *
 * Renders GET /api/attack-exposure/:client_id: a tactic rollup (findings per ATT&CK tactic) and
 * the top exposed techniques with a severity breakdown. This is the operational counterpart to the
 * static coverage matrix — "what is this client actually exposed to", straight from the engine.
 */

const SEV_COLOR = { critical: '#f43f5e', high: '#fb923c', medium: '#fbbf24', low: '#38bdf8', info: '#94a3b8', other: '#64748b' }
const SEV_ORDER = ['critical', 'high', 'medium', 'low', 'info', 'other']

export const EXPOSURE_CSV_HEADER = ['technique', 'name', 'tactic', 'count', 'critical', 'high', 'medium', 'low', 'info', 'other']

/** Pure: flatten technique stats into CSV rows aligned with EXPOSURE_CSV_HEADER. */
export function techniqueCsvRows(techniques) {
  if (!Array.isArray(techniques)) return []
  return techniques.map((t) => [
    t?.technique ?? '',
    t?.name ?? '',
    t?.tactic ?? '',
    t?.count ?? 0,
    t?.critical ?? 0,
    t?.high ?? 0,
    t?.medium ?? 0,
    t?.low ?? 0,
    t?.info ?? 0,
    t?.other ?? 0,
  ])
}

/** Pure: max finding_count across tactics (for bar scaling); >=1 to avoid divide-by-zero. */
export function maxTacticCount(tactics) {
  if (!Array.isArray(tactics) || tactics.length === 0) return 1
  return Math.max(1, ...tactics.map((x) => Number(x?.finding_count) || 0))
}

function SeverityBar({ stat }) {
  const total = Number(stat?.count) || 0
  if (!total) return null
  return (
    <div className="flex h-1.5 w-full max-w-[180px] rounded-full overflow-hidden bg-white/5">
      {SEV_ORDER.map((k) => {
        const v = Number(stat[k]) || 0
        if (!v) return null
        return <div key={k} style={{ width: `${(v / total) * 100}%`, background: SEV_COLOR[k] }} title={`${k}: ${v}`} />
      })}
    </div>
  )
}

export default function AttackExposurePanel({ clientId }) {
  const { t } = useTranslation()
  const [data, setData] = useState(null)
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState(null)
  const [searchQuery, setSearchQuery] = useState('')

  const load = useCallback(async (id) => {
    if (id == null) { setData(null); return }
    setLoading(true)
    setError(null)
    try {
      const r = await apiFetch(`/api/attack-exposure/${encodeURIComponent(id)}?limit=2000`)
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

  const tactics = Array.isArray(data?.tactics) ? data.tactics : []
  const techniques = useMemo(() => (Array.isArray(data?.techniques) ? data.techniques : []), [data])

  // Client-side filter over the already-loaded technique rollup (a bounded, tenant-scoped
  // set — no server round-trip needed to search it).
  const filteredTechniques = useMemo(
    () =>
      techniques.filter((tech) =>
        rowMatchesQuery(searchQuery, [tech?.technique, tech?.name, tech?.tactic, tech?.count, tech?.critical, tech?.high, tech?.medium, tech?.low]),
      ),
    [techniques, searchQuery],
  )
  const topTechniques = filteredTechniques.slice(0, 12)
  const barMax = maxTacticCount(tactics)

  const handleRefresh = useCallback(() => load(clientId), [load, clientId])
  const exportCsv = useCallback(
    () => downloadCsv(techniqueCsvRows(filteredTechniques), EXPOSURE_CSV_HEADER, 'weissman-attack-exposure'),
    [filteredTechniques],
  )
  const exportPdf = useCallback(
    () => exportRowsPdf('Weissman ATT&CK Exposure', EXPOSURE_CSV_HEADER, techniqueCsvRows(filteredTechniques), 'weissman-attack-exposure'),
    [filteredTechniques],
  )

  return (
    <div className="bg-black/40 backdrop-blur-md border border-white/10 rounded-xl overflow-hidden">
      <div className="px-4 pt-4">
        <EvidenceNotice>
          Live exposure from GET /api/attack-exposure/:clientId — MITRE ATT&amp;CK tactic and
          technique rollup straight from the engine. No fabricated exposure telemetry.
        </EvidenceNotice>
      </div>
      <div className="p-4 border-b border-white/10 flex items-center justify-between gap-3 flex-wrap">
        <h3 className="text-sm font-semibold text-white flex items-center gap-2">
          <Crosshair className="w-4 h-4 text-rose-400" />
          {t('pages.threatAnalysis.exposure_heading')}
        </h3>
        <div className="flex items-center gap-3">
          <ShellScanActions
            onRefresh={handleRefresh}
            onExport={exportCsv}
            refreshLoading={loading}
            exportDisabled={!filteredTechniques.length}
          />
          <Button
            variant="unstyled"
            type="button"
            onClick={exportPdf}
            disabled={!filteredTechniques.length}
            title={t('common.export_pdf')}
            className="inline-flex items-center gap-1.5 px-2.5 py-1.5 rounded-md text-[11px] font-semibold border border-white/15 text-white/70 hover:bg-white/10 disabled:opacity-40 transition-colors"
          >
            <FileText className="w-3.5 h-3.5" />
            {t('common.export_pdf')}
          </Button>
        </div>
      </div>

      {clientId == null ? (
        <div className="p-4"><EmptyState compact icon="shield" title={t('pages.threatAnalysis.exposure_no_client')} /></div>
      ) : error ? (
        <div className="p-4 text-sm text-rose-300 flex items-center gap-2"><AlertTriangle className="w-4 h-4 shrink-0" />{t('pages.threatAnalysis.exposure_error', { error })}</div>
      ) : loading ? (
        <div className="p-4"><SkeletonTable rows={5} cols={3} /></div>
      ) : techniques.length === 0 ? (
        <div className="p-4"><EmptyState compact icon="shield" title={t('pages.threatAnalysis.exposure_empty')} /></div>
      ) : (
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-0">
          {/* Tactic rollup */}
          <div className="p-4 border-b lg:border-b-0 lg:border-r border-white/5">
            <div className="text-[10px] uppercase tracking-wider text-white/40 mb-3">{t('pages.threatAnalysis.exposure_tactics')}</div>
            <div className="space-y-2">
              {tactics.map((ta) => (
                <div key={ta.tactic} className="flex items-center gap-2">
                  <div className="w-40 shrink-0 text-[11px] text-white/70 truncate" title={ta.tactic}>{ta.tactic}</div>
                  <div className="flex-1 h-2 rounded-full bg-white/5 overflow-hidden">
                    <div className="h-full bg-gradient-to-r from-rose-500/70 to-amber-400/70" style={{ width: `${((Number(ta.finding_count) || 0) / barMax) * 100}%` }} />
                  </div>
                  <div className="w-16 shrink-0 text-right text-[10px] font-mono text-white/45 tabular-nums">
                    {ta.finding_count}·{ta.technique_count}t
                  </div>
                </div>
              ))}
            </div>
          </div>

          {/* Top techniques */}
          <div className="p-4">
            <div className="flex items-center justify-between gap-2 mb-3">
              <div className="text-[10px] uppercase tracking-wider text-white/40">{t('pages.threatAnalysis.exposure_top')}</div>
              <div className="relative">
                <Search className="w-3 h-3 text-white/30 absolute left-2 top-1/2 -translate-y-1/2 pointer-events-none" />
                <input
                  type="search"
                  value={searchQuery}
                  onChange={(e) => setSearchQuery(e.target.value)}
                  placeholder={t('common.search')}
                  aria-label={t('common.search')}
                  className="w-32 pl-6 pr-2 py-1 rounded-md text-[11px] bg-black/40 border border-white/10 text-white/80 placeholder-white/30 focus:outline-none focus:border-rose-500/40"
                />
              </div>
            </div>
            {topTechniques.length === 0 ? (
              <div className="text-[11px] text-white/35">{t('pages.threatAnalysis.exposure_no_match')}</div>
            ) : (
            <div className="space-y-2.5">
              {topTechniques.map((tech) => (
                <div key={tech.technique} className="flex items-center gap-2">
                  <div className="min-w-0 flex-1">
                    <div className="flex items-center gap-1.5">
                      <span className="text-[11px] font-mono text-rose-300">{tech.technique}</span>
                      <span className="text-[11px] text-white/70 truncate">{tech.name || tech.tactic}</span>
                    </div>
                    <SeverityBar stat={tech} />
                  </div>
                  <div className="w-8 shrink-0 text-right text-xs font-bold tabular-nums text-white">{tech.count}</div>
                </div>
              ))}
            </div>
            )}
          </div>
        </div>
      )}
    </div>
  )
}
