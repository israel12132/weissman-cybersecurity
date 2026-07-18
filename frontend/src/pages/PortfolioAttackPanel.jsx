import { useCallback, useEffect, useMemo, useState } from 'react'
import { useTranslation } from 'react-i18next'
import { Crosshair, FileText, Search } from 'lucide-react'
import { apiFetch } from '../lib/apiBase'
import EvidenceNotice from '../components/ui/EvidenceNotice'
import Button from '../components/ui/Button'
import ShellScanActions from '../components/engine/ShellScanActions'
import { exportRowsCsv, exportRowsPdf, rowMatchesQuery } from '../lib/pageExport'

/**
 * PortfolioAttackPanel — fleet-wide MITRE ATT&CK exposure across all clients.
 *
 * Renders GET /api/portfolio/attack-exposure (tenant-scoped): the techniques the whole client base
 * is most exposed to, each with the total findings and how many distinct clients are affected — so
 * an MSSP SOC aligns detections to what's actually widespread, not just one noisy client.
 */

/** CSV/PDF columns for the fleet ATT&CK exposure rollup. Exported for tests. */
export const PORTFOLIO_ATTACK_CSV_HEADER = ['technique', 'name', 'tactic', 'finding_count', 'client_count']

/** Pure: fleet techniques → export rows. Exported for tests. */
export function portfolioAttackRows(techniques) {
  return (Array.isArray(techniques) ? techniques : []).map((tech) => [
    tech?.technique ?? '',
    tech?.name ?? '',
    tech?.tactic ?? '',
    tech?.finding_count ?? 0,
    tech?.client_count ?? 0,
  ])
}

/** Pure: largest fleet finding_count (for bar scaling); >=1 to avoid a zero denominator. */
export function maxFindingCount(techniques) {
  if (!Array.isArray(techniques) || techniques.length === 0) return 1
  return Math.max(1, ...techniques.map((t) => Number(t?.finding_count) || 0))
}

export default function PortfolioAttackPanel() {
  const { t } = useTranslation()
  const [data, setData] = useState(null)
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState(null)
  const [searchQuery, setSearchQuery] = useState('')

  const load = useCallback(async () => {
    setLoading(true)
    setError(null)
    try {
      const r = await apiFetch('/api/portfolio/attack-exposure')
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

  const techniques = useMemo(() => (Array.isArray(data?.techniques) ? data.techniques : []), [data])

  // Client-side filter over the already-loaded fleet rollup (a bounded, tenant-scoped
  // aggregate — no server round-trip needed to search it).
  const filteredTechniques = useMemo(
    () => techniques.filter((tech) => rowMatchesQuery(searchQuery, [tech?.technique, tech?.name, tech?.tactic, tech?.finding_count, tech?.client_count])),
    [techniques, searchQuery],
  )

  const handleRefresh = useCallback(() => load(), [load])
  const exportCsv = useCallback(
    () => exportRowsCsv(PORTFOLIO_ATTACK_CSV_HEADER, portfolioAttackRows(filteredTechniques), 'weissman-portfolio-attack'),
    [filteredTechniques],
  )
  const exportPdf = useCallback(
    () => exportRowsPdf('Weissman Fleet ATT&CK Exposure', PORTFOLIO_ATTACK_CSV_HEADER, portfolioAttackRows(filteredTechniques), 'weissman-portfolio-attack'),
    [filteredTechniques],
  )

  if (loading || error || techniques.length === 0) return null

  const top = filteredTechniques.slice(0, 10)
  const barMax = maxFindingCount(techniques)

  return (
    <div className="bg-black/40 backdrop-blur-md border border-white/10 rounded-xl overflow-hidden">
      <div className="px-4 pt-4">
        <EvidenceNotice>
          Live fleet exposure from GET /api/portfolio/attack-exposure — tenant-wide ATT&amp;CK
          techniques aggregated across all clients. No fabricated exposure telemetry.
        </EvidenceNotice>
      </div>
      <div className="p-4 border-b border-white/10 flex items-center justify-between gap-3 flex-wrap">
        <h3 className="text-sm font-semibold text-white flex items-center gap-2">
          <Crosshair className="w-4 h-4 text-rose-400" />
          {t('clients_page.fleet_attack_heading', { defaultValue: 'Fleet ATT&CK Exposure' })}
        </h3>
        <div className="flex items-center gap-3">
          <span className="text-[10px] font-mono text-white/40">
            {t('clients_page.fleet_attack_summary', {
              techniques: Number(data.unique_techniques) || techniques.length,
              clients: Number(data.exposed_clients) || 0,
              defaultValue: '{{techniques}} techniques · {{clients}} clients exposed',
            })}
          </span>
          <div className="relative">
            <Search className="w-3 h-3 text-white/30 absolute left-2 top-1/2 -translate-y-1/2 pointer-events-none" />
            <input
              type="search"
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
              placeholder={t('common.search', { defaultValue: 'Search' })}
              aria-label={t('common.search', { defaultValue: 'Search techniques' })}
              className="w-32 pl-6 pr-2 py-1 rounded-md text-[11px] bg-black/40 border border-white/10 text-white/80 placeholder-white/30 focus:outline-none focus:border-rose-500/40"
            />
          </div>
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
            title={t('common.export_pdf', { defaultValue: 'Export PDF' })}
            className="inline-flex items-center gap-1.5 px-2.5 py-1.5 rounded-md text-[11px] font-semibold border border-white/15 text-white/70 hover:bg-white/10 disabled:opacity-40 transition-colors"
          >
            <FileText className="w-3.5 h-3.5" />
            {t('common.export_pdf', { defaultValue: 'PDF' })}
          </Button>
        </div>
      </div>

      <div className="p-4 space-y-2">
        {top.length === 0 ? (
          <div className="text-[11px] text-white/35">{t('clients_page.fleet_attack_none', { defaultValue: 'No techniques matched this search.' })}</div>
        ) : (
          top.map((tech) => (
            <div key={tech.technique} className="flex items-center gap-2">
              <span className="w-20 shrink-0 text-[11px] font-mono text-rose-300">{tech.technique}</span>
              <span className="hidden sm:block w-44 shrink-0 text-[11px] text-white/60 truncate" title={tech.name || tech.tactic}>
                {tech.name || tech.tactic}
              </span>
              <div className="flex-1 h-2 rounded-full bg-white/5 overflow-hidden">
                <div className="h-full rounded-full bg-gradient-to-r from-rose-500/70 to-amber-400/70" style={{ width: `${((Number(tech.finding_count) || 0) / barMax) * 100}%` }} />
              </div>
              <span className="w-10 shrink-0 text-right text-xs font-bold tabular-nums text-white">{tech.finding_count}</span>
              <span className="w-16 shrink-0 text-right text-[10px] font-mono text-violet-300" title={t('clients_page.fleet_attack_clients_hint', { defaultValue: 'clients exposed' })}>
                {t('clients_page.fleet_attack_clients', { count: tech.client_count, defaultValue: '{{count}} cli' })}
              </span>
            </div>
          ))
        )}
      </div>
    </div>
  )
}
