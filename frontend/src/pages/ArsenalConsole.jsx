import { useCallback, useEffect, useMemo, useState } from 'react'
import { useTranslation } from 'react-i18next'
import { Swords, Rocket, ShieldAlert, CheckCircle2, XCircle, Loader2, FileText, Search } from 'lucide-react'
import { apiFetch } from '../lib/apiBase'
import EvidenceNotice from '../components/ui/EvidenceNotice'
import ShellScanActions from '../components/engine/ShellScanActions'
import { exportRowsCsv, exportRowsPdf, rowMatchesQuery } from '../lib/pageExport'

/** CSV/PDF columns for the recommended-engine plan. Exported for tests. */
export const ARSENAL_CSV_HEADER = ['engine_id', 'addressable_findings']

/** Pure: recommended engines → export rows. Exported for tests. */
export function arsenalRows(recommended) {
  return (Array.isArray(recommended) ? recommended : []).map((e) => [
    e?.engine_id ?? '',
    e?.addressable_findings ?? 0,
  ])
}

/**
 * ArsenalConsole — the system's self-aware, one-click response to a client's threat exposure.
 *
 * Reads GET /api/arsenal/recommendation/:client_id (which crosses the client's ATT&CK exposure
 * against our engine arsenal) and turns it into action: a ranked list of the engines to deploy,
 * the coverage the arsenal gives, and the capability gaps it can't. "Deploy recommended" launches
 * the ranked engines against the client via POST /api/command-center/scan — press once, done.
 */

/** Pure: colour for a 0..100 coverage percentage. Exported for tests. */
export function coverageTone(pct) {
  const n = Number(pct)
  if (!Number.isFinite(n)) return '#94a3b8'
  if (n >= 90) return '#34d399'
  if (n >= 70) return '#a3e635'
  if (n >= 40) return '#fbbf24'
  return '#f43f5e'
}

/** Pure: the deploy set — valid, distinct engine ids from the recommendations. `cap` defaults high
 *  so the full recommended plan deploys (no artificial limit); pass a smaller cap to bound it. */
export function deployList(recommended, cap = 200) {
  if (!Array.isArray(recommended)) return []
  const seen = new Set()
  const out = []
  for (const r of recommended) {
    const id = r && typeof r.engine_id === 'string' ? r.engine_id.trim() : ''
    if (id && !seen.has(id)) {
      seen.add(id)
      out.push(id)
    }
    if (out.length >= cap) break
  }
  return out
}

/** Pure: first domain from a client's `domains` field (JSON-string array or array). Exported. */
export function parseFirstDomain(domains) {
  let arr = domains
  if (typeof domains === 'string') {
    try { arr = JSON.parse(domains) } catch { arr = domains ? [domains] : [] }
  }
  if (!Array.isArray(arr)) return ''
  const first = arr.find((d) => typeof d === 'string' && d.trim())
  return first ? first.trim() : ''
}

const STATUS_ICON = { queued: CheckCircle2, running: Loader2, failed: XCircle }
const STATUS_TONE = { queued: 'text-emerald-300', running: 'text-cyan-300', failed: 'text-rose-300' }

export default function ArsenalConsole({ clientId }) {
  const { t } = useTranslation()
  const [data, setData] = useState(null)
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState(null)
  const [target, setTarget] = useState('')
  const [deploying, setDeploying] = useState(false)
  const [launchStatus, setLaunchStatus] = useState({})
  const [searchQuery, setSearchQuery] = useState('')

  const load = useCallback(async (id) => {
    if (id == null) { setData(null); return }
    setLoading(true)
    setError(null)
    setLaunchStatus({})
    try {
      const r = await apiFetch(`/api/arsenal/recommendation/${encodeURIComponent(id)}`)
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

  // Best-effort target resolution from the client's first domain (for the launch payload).
  const resolveTarget = useCallback(async (id) => {
    if (id == null) { setTarget(''); return }
    try {
      const r = await apiFetch('/api/clients')
      if (!r.ok) return
      const d = await r.json().catch(() => [])
      const list = Array.isArray(d) ? d : d?.clients || []
      const c = list.find((x) => String(x.id) === String(id))
      setTarget(parseFirstDomain(c?.domains))
    } catch { /* target stays empty; backend may still resolve it */ }
  }, [])

  useEffect(() => { load(clientId); resolveTarget(clientId) }, [clientId, load, resolveTarget])

  const recommended = useMemo(
    () => (Array.isArray(data?.recommended_engines) ? data.recommended_engines : []),
    [data],
  )
  const gaps = Array.isArray(data?.gaps) ? data.gaps : []
  const plan = useMemo(() => deployList(recommended), [recommended])

  // Client-side filter over the already-loaded recommendation set (a bounded, tenant-
  // scoped rollup — no server round-trip needed to search it).
  const filteredRecommended = useMemo(
    () => recommended.filter((e) => rowMatchesQuery(searchQuery, [e?.engine_id, e?.addressable_findings])),
    [recommended, searchQuery],
  )

  const handleRefresh = useCallback(() => load(clientId), [load, clientId])
  const exportCsv = useCallback(
    () => exportRowsCsv(ARSENAL_CSV_HEADER, arsenalRows(filteredRecommended), 'weissman-arsenal-console'),
    [filteredRecommended],
  )
  const exportPdf = useCallback(
    () =>
      exportRowsPdf('Weissman Arsenal Console', ARSENAL_CSV_HEADER, arsenalRows(filteredRecommended), 'weissman-arsenal-console'),
    [filteredRecommended],
  )

  // Deploy the recommended plan through the stealth batch endpoint (rate-limited, jittered, rotated
  // identity) instead of a burst — so the recommended one-click is as WAF-safe as "Run all".
  const deploy = useCallback(async () => {
    if (deploying || plan.length === 0 || clientId == null) return
    setDeploying(true)
    setLaunchStatus({})
    try {
      const r = await apiFetch('/api/arsenal/deploy', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ client_id: clientId, target, engines: plan }),
      })
      await r.json().catch(() => ({}))
      const state = r.ok ? 'queued' : 'failed'
      setLaunchStatus(Object.fromEntries(plan.map((id) => [id, state])))
    } catch {
      setLaunchStatus(Object.fromEntries(plan.map((id) => [id, 'failed'])))
    } finally {
      setDeploying(false)
    }
  }, [deploying, plan, clientId, target])

  if (clientId == null || loading) return null
  if (error) return null
  if (recommended.length === 0 && gaps.length === 0) return null

  const coverage = Number(data?.coverage_pct)

  return (
    <div className="bg-black/40 backdrop-blur-md border border-white/10 rounded-xl overflow-hidden">
      <div className="px-4 pt-4">
        <EvidenceNotice>
          Live recommendation from GET /api/arsenal/recommendation/:client_id — ATT&amp;CK exposure
          crossed against the tenant-scoped engine arsenal. No fabricated engine telemetry.
        </EvidenceNotice>
      </div>
      <div className="p-4 border-b border-white/10 flex items-center justify-between gap-3 flex-wrap">
        <h3 className="text-sm font-semibold text-white flex items-center gap-2">
          <Swords className="w-4 h-4 text-cyan-400" />
          {t('pages.threatAnalysis.arsenal_heading', { defaultValue: 'Arsenal Console' })}
        </h3>
        <div className="flex items-center gap-3">
          <span className="text-[11px] font-mono" style={{ color: coverageTone(coverage) }}>
            {t('pages.threatAnalysis.arsenal_coverage', { pct: Number.isFinite(coverage) ? coverage.toFixed(0) : '—', defaultValue: '{{pct}}% covered' })}
          </span>
          <span className="text-[10px] font-mono text-white/35">
            {t('pages.threatAnalysis.arsenal_inventory', { engines: data?.arsenal_engine_count ?? 0, defaultValue: '{{engines}} engines in arsenal' })}
          </span>
          <ShellScanActions
            onRefresh={handleRefresh}
            onExport={exportCsv}
            refreshLoading={loading}
            exportDisabled={!filteredRecommended.length}
          />
          <button
            type="button"
            onClick={exportPdf}
            disabled={!filteredRecommended.length}
            title={t('common.export_pdf', { defaultValue: 'Export PDF' })}
            className="inline-flex items-center gap-1.5 px-2.5 py-1.5 rounded-md text-[11px] font-semibold border border-white/15 text-white/70 hover:bg-white/10 disabled:opacity-40 transition-colors"
          >
            <FileText className="w-3.5 h-3.5" />
            {t('common.export_pdf', { defaultValue: 'PDF' })}
          </button>
          {plan.length > 0 && (
            <button
              type="button"
              onClick={deploy}
              disabled={deploying}
              className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-md text-[11px] font-semibold border border-cyan-500/40 text-cyan-200 bg-cyan-500/10 hover:bg-cyan-500/20 disabled:opacity-50 disabled:cursor-wait transition-colors"
            >
              {deploying ? <Loader2 className="w-3.5 h-3.5 animate-spin" /> : <Rocket className="w-3.5 h-3.5" />}
              {t('pages.threatAnalysis.arsenal_deploy', { count: plan.length, defaultValue: 'Deploy recommended ({{count}})' })}
            </button>
          )}
        </div>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-0">
        {/* Recommended engines (the one-click plan) */}
        <div className="p-4 border-b lg:border-b-0 lg:border-r border-white/5">
          <div className="flex items-center justify-between gap-2 mb-3">
            <div className="text-[10px] uppercase tracking-wider text-white/40">{t('pages.threatAnalysis.arsenal_recommended', { defaultValue: 'Recommended engines' })}</div>
            <div className="relative">
              <Search className="w-3 h-3 text-white/30 absolute left-2 top-1/2 -translate-y-1/2 pointer-events-none" />
              <input
                type="search"
                value={searchQuery}
                onChange={(e) => setSearchQuery(e.target.value)}
                placeholder={t('common.search', { defaultValue: 'Search' })}
                aria-label={t('common.search', { defaultValue: 'Search engines' })}
                className="w-32 pl-6 pr-2 py-1 rounded-md text-[11px] bg-black/40 border border-white/10 text-white/80 placeholder-white/30 focus:outline-none focus:border-cyan-500/40"
              />
            </div>
          </div>
          {filteredRecommended.length === 0 ? (
            <div className="text-[11px] text-white/35">{t('pages.threatAnalysis.arsenal_none', { defaultValue: 'No arsenal engines matched this exposure.' })}</div>
          ) : (
            <div className="space-y-2">
              {filteredRecommended.slice(0, 12).map((e) => {
                const st = launchStatus[e.engine_id]
                const Icon = st ? STATUS_ICON[st] : null
                return (
                  <div key={e.engine_id} className="flex items-center gap-2">
                    <span className="flex-1 min-w-0 text-[12px] font-mono text-cyan-200 truncate">{e.engine_id}</span>
                    {Icon && <Icon className={`w-3.5 h-3.5 shrink-0 ${STATUS_TONE[st]} ${st === 'running' ? 'animate-spin' : ''}`} />}
                    <span className="text-[10px] font-mono text-white/40 shrink-0">
                      {t('pages.threatAnalysis.arsenal_addressable', { count: e.addressable_findings, defaultValue: '{{count}} findings' })}
                    </span>
                  </div>
                )
              })}
            </div>
          )}
        </div>

        {/* Capability gaps (what arsenal we still need) */}
        <div className="p-4">
          <div className="text-[10px] uppercase tracking-wider text-white/40 mb-3 flex items-center gap-1.5">
            <ShieldAlert className="w-3.5 h-3.5 text-amber-400" />
            {t('pages.threatAnalysis.arsenal_gaps', { defaultValue: 'Capability gaps' })}
          </div>
          {gaps.length === 0 ? (
            <div className="text-[11px] text-emerald-300/80">{t('pages.threatAnalysis.arsenal_no_gaps', { defaultValue: 'The arsenal covers all detected exposure.' })}</div>
          ) : (
            <div className="flex flex-wrap gap-1.5">
              {gaps.slice(0, 16).map((g) => (
                <span key={g.technique} className="inline-flex items-center gap-1 px-1.5 py-0.5 rounded text-[10px] font-mono border border-amber-500/30 text-amber-300 bg-amber-500/10" title={t('pages.threatAnalysis.arsenal_gap_hint', { count: g.finding_count, defaultValue: '{{count}} findings, no engine' })}>
                  {g.technique}
                </span>
              ))}
            </div>
          )}
        </div>
      </div>
    </div>
  )
}
