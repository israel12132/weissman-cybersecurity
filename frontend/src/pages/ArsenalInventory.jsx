import { useCallback, useEffect, useMemo, useState } from 'react'
import { useTranslation } from 'react-i18next'
import { Boxes, Search, Play, Loader2, CheckCircle2, XCircle, Rocket, FileText } from 'lucide-react'
import { apiFetch } from '../utils/apiFetch'
import { useLaunchEngineScan } from '../hooks/useLaunchEngineScan'
import EvidenceNotice from '../components/ui/EvidenceNotice'
import Button from '../components/ui/Button'
import ShellScanActions from '../components/engine/ShellScanActions'
import { exportRowsCsv, exportRowsPdf } from '../lib/pageExport'
import { parseFirstDomain } from './ArsenalConsole'

/**
 * ArsenalInventory — the complete, browsable, runnable arsenal.
 *
 * Reads GET /api/arsenal/catalog (every production engine + its authoritative classification,
 * category, and ATT&CK mapping) and lets the operator search the whole fleet by name/category and
 * launch ANY engine against the selected client in real time. This is the "run all of them" surface:
 * the full arsenal at your fingertips, not a curated slice.
 */

const KIND_TONE = {
  real_probe: { label: 'live', cls: 'text-emerald-300 border-emerald-500/30 bg-emerald-500/10' },
  alias: { label: 'alias', cls: 'text-sky-300 border-sky-500/30 bg-sky-500/10' },
  agent_required: { label: 'agent', cls: 'text-amber-300 border-amber-500/30 bg-amber-500/10' },
  special: { label: 'async', cls: 'text-violet-300 border-violet-500/30 bg-violet-500/10' },
}
const MAX_RENDER = 90

/** CSV/PDF columns for the arsenal catalog. Exported for tests. */
export const ARSENAL_INV_CSV_HEADER = ['id', 'kind', 'category', 'techniques']

/** Pure: catalog engines → export rows. Exported for tests. */
export function arsenalInventoryRows(engines) {
  return (Array.isArray(engines) ? engines : []).map((e) => [
    e?.id ?? '',
    e?.kind ?? '',
    e?.category ?? '',
    Array.isArray(e?.techniques) ? e.techniques.join('; ') : '',
  ])
}

/** Pure: does an engine match a lowercase query over id, category, and techniques? Exported. */
export function matchesQuery(engine, q) {
  if (!q) return true
  const hay = `${engine?.id ?? ''} ${engine?.category ?? ''} ${(engine?.techniques || []).join(' ')}`.toLowerCase()
  return hay.includes(q)
}

/** Pure: filter engines by free-text query and optional exact category. Exported for tests. */
export function filterEngines(engines, query, category) {
  if (!Array.isArray(engines)) return []
  const q = String(query || '').trim().toLowerCase()
  return engines.filter((e) => (!category || e?.category === category) && matchesQuery(e, q))
}

/** Pure: drop duplicate-alias engines, keeping only distinct operations. Exported for tests. */
export function excludeAliases(engines) {
  if (!Array.isArray(engines)) return []
  return engines.filter((e) => e?.kind !== 'alias')
}

/** Pure: distinct engine ids from a filtered set, capped for a single stealth batch. Exported. */
export function batchEngineIds(engines, cap = 500) {
  if (!Array.isArray(engines)) return []
  const seen = new Set()
  const out = []
  for (const e of engines) {
    const id = e && typeof e.id === 'string' ? e.id.trim() : ''
    if (id && !seen.has(id)) {
      seen.add(id)
      out.push(id)
    }
    if (out.length >= cap) break
  }
  return out
}

/** Pure: humanise a millisecond ETA (e.g. 4200 → "4s", 95000 → "1m 35s"). Exported for tests. */
export function formatEta(ms) {
  const n = Number(ms)
  if (!Number.isFinite(n) || n <= 0) return '0s'
  const s = Math.round(n / 1000)
  if (s < 60) return `${s}s`
  const m = Math.floor(s / 60)
  const rem = s % 60
  return rem ? `${m}m ${rem}s` : `${m}m`
}

const STATUS_ICON = { queued: CheckCircle2, running: Loader2, failed: XCircle }
const STATUS_TONE = { queued: 'text-emerald-300', running: 'text-cyan-300', failed: 'text-rose-300' }

export default function ArsenalInventory({ clientId }) {
  const { t } = useTranslation()
  const launch = useLaunchEngineScan(clientId)
  const [data, setData] = useState(null)
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState(null)
  const [query, setQuery] = useState('')
  const [category, setCategory] = useState('')
  const [target, setTarget] = useState('')
  const [runStatus, setRunStatus] = useState({})
  const [deploying, setDeploying] = useState(false)
  const [batch, setBatch] = useState(null)
  const [distinctOnly, setDistinctOnly] = useState(false)

  const load = useCallback(async () => {
    setLoading(true)
    setError(null)
    try {
      const d = await apiFetch('/api/arsenal/catalog')
      setData(d && typeof d === 'object' ? d : null)
    } catch (e) {
      setError(e?.message || 'load failed')
      setData(null)
    } finally {
      setLoading(false)
    }
  }, [])

  const resolveTarget = useCallback(async (id) => {
    if (id == null) { setTarget(''); return }
    try {
      const d = await apiFetch('/api/clients')
      const list = Array.isArray(d) ? d : d?.clients || []
      const c = list.find((x) => String(x.id) === String(id))
      setTarget(parseFirstDomain(c?.domains))
    } catch { /* best-effort */ }
  }, [])

  useEffect(() => { load() }, [load])
  useEffect(() => { resolveTarget(clientId) }, [clientId, resolveTarget])

  const engines = useMemo(() => (Array.isArray(data?.engines) ? data.engines : []), [data])
  const byCategory = useMemo(
    () => (data?.by_category && typeof data.by_category === 'object' ? data.by_category : {}),
    [data],
  )
  const categories = useMemo(() => Object.keys(byCategory).sort(), [byCategory])

  const distinctCount = useMemo(() => excludeAliases(engines).length, [engines])
  const base = useMemo(() => (distinctOnly ? excludeAliases(engines) : engines), [engines, distinctOnly])
  const filtered = useMemo(() => filterEngines(base, query, category), [base, query, category])
  const shown = filtered.slice(0, MAX_RENDER)
  const batchIds = useMemo(() => batchEngineIds(filtered), [filtered])

  const runAll = useCallback(async () => {
    if (deploying || clientId == null || batchIds.length === 0) return
    setDeploying(true)
    setBatch(null)
    try {
      const d = await apiFetch('/api/arsenal/deploy', {
        method: 'POST',
        body: { client_id: clientId, target, engines: batchIds },
      })
      setBatch({ ok: true, ...d })
    } catch (e) {
      setBatch({ ok: false, detail: e?.message || 'deploy failed' })
    } finally {
      setDeploying(false)
    }
  }, [deploying, clientId, target, batchIds])

  const run = useCallback(async (engineId) => {
    if (clientId == null || runStatus[engineId] === 'running') return
    setRunStatus((s) => ({ ...s, [engineId]: 'running' }))
    try {
      const res = await launch({ engineId, clientId, target })
      setRunStatus((s) => ({ ...s, [engineId]: res.ok ? 'queued' : 'failed' }))
    } catch {
      setRunStatus((s) => ({ ...s, [engineId]: 'failed' }))
    }
  }, [clientId, target, runStatus, launch])

  const handleRefresh = useCallback(() => load(), [load])
  const exportCsv = useCallback(
    () => exportRowsCsv(ARSENAL_INV_CSV_HEADER, arsenalInventoryRows(filtered), 'weissman-arsenal-inventory'),
    [filtered],
  )
  const exportPdf = useCallback(
    () => exportRowsPdf('Weissman Arsenal Inventory', ARSENAL_INV_CSV_HEADER, arsenalInventoryRows(filtered), 'weissman-arsenal-inventory'),
    [filtered],
  )

  if (loading) return null
  if (error || engines.length === 0) return null

  return (
    <div className="bg-black/40 backdrop-blur-md border border-white/10 rounded-xl overflow-hidden">
      <div className="px-4 pt-4">
        <EvidenceNotice>
          Live catalog from GET /api/arsenal/catalog — every production engine with its authoritative
          kind, category, and ATT&amp;CK mapping. No fabricated engine telemetry.
        </EvidenceNotice>
      </div>
      <div className="p-4 border-b border-white/10 flex items-center justify-between gap-3 flex-wrap">
        <h3 className="text-sm font-semibold text-white flex items-center gap-2">
          <Boxes className="w-4 h-4 text-cyan-400" />
          {t('pages.threatAnalysis.inv_heading', { defaultValue: 'Full Arsenal' })}
          <span className="text-[10px] font-mono text-white/40">
            {t('pages.threatAnalysis.inv_count2', { count: data?.engine_count ?? engines.length, distinct: distinctCount, defaultValue: '{{count}} engines · {{distinct}} distinct' })}
          </span>
        </h3>
        <div className="flex items-center gap-2">
          <div className="relative">
            <Search className="absolute left-2.5 top-1/2 -translate-y-1/2 w-3.5 h-3.5 text-white/25" />
            <input
              type="search"
              value={query}
              onChange={(e) => setQuery(e.target.value)}
              placeholder={t('pages.threatAnalysis.inv_search', { defaultValue: 'Search the arsenal…' })}
              aria-label={t('pages.threatAnalysis.inv_search', { defaultValue: 'Search the arsenal' })}
              className="bg-black/40 border border-white/10 rounded-lg pl-8 pr-3 py-1.5 text-xs text-white/80 placeholder-white/25 font-mono focus:outline-none focus:border-cyan-500/40 w-44 md:w-56"
            />
          </div>
          <ShellScanActions
            onRefresh={handleRefresh}
            onExport={exportCsv}
            refreshLoading={loading}
            exportDisabled={!filtered.length}
          />
          <Button
            variant="unstyled"
            type="button"
            onClick={exportPdf}
            disabled={!filtered.length}
            title={t('common.export_pdf', { defaultValue: 'Export PDF' })}
            className="inline-flex items-center gap-1.5 px-2.5 py-1.5 rounded-md text-[11px] font-semibold border border-white/15 text-white/70 hover:bg-white/10 disabled:opacity-40 transition-colors"
          >
            <FileText className="w-3.5 h-3.5" />
            {t('common.export_pdf', { defaultValue: 'PDF' })}
          </Button>
          {clientId != null && batchIds.length > 0 && (
            <Button
              variant="unstyled"
              type="button"
              onClick={runAll}
              disabled={deploying}
              title={t('pages.threatAnalysis.inv_runall_hint', { defaultValue: 'Stealth-dispatch every matching engine (rate-limited, jittered, WAF-safe)' })}
              className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-md text-[11px] font-semibold border border-rose-500/40 text-rose-200 bg-rose-500/10 hover:bg-rose-500/20 disabled:opacity-50 disabled:cursor-wait transition-colors whitespace-nowrap"
            >
              {deploying ? <Loader2 className="w-3.5 h-3.5 animate-spin" /> : <Rocket className="w-3.5 h-3.5" />}
              {t('pages.threatAnalysis.inv_runall', { count: batchIds.length, defaultValue: 'Run all ({{count}}) — stealth' })}
            </Button>
          )}
        </div>
      </div>

      {batch && (
        <div className={`px-4 py-2 border-b text-[11px] font-mono ${batch.ok ? 'border-emerald-500/20 bg-emerald-500/5 text-emerald-200' : 'border-rose-500/20 bg-rose-500/5 text-rose-200'}`}>
          {batch.ok
            ? t('pages.threatAnalysis.inv_batch_ok', {
                count: batch.engines_queued ?? 0,
                waves: batch.plan?.waves ?? 0,
                eta: formatEta(batch.plan?.estimated_duration_ms),
                defaultValue: 'Stealth batch queued: {{count}} engines · {{waves}} waves · ~{{eta}} drip',
              })
            : t('pages.threatAnalysis.inv_batch_err', { detail: batch.detail, defaultValue: 'Deploy failed: {{detail}}' })}
        </div>
      )}

      {/* Category filter */}
      <div className="px-4 py-2 border-b border-white/5 flex items-center gap-1.5 flex-wrap">
        <Button
          variant="unstyled"
          type="button"
          onClick={() => setDistinctOnly((v) => !v)}
          title={t('pages.threatAnalysis.inv_distinct_hint', { defaultValue: 'Hide duplicate aliases — show only distinct operations' })}
          className={`px-2 py-0.5 rounded text-[10px] font-mono border transition-colors ${distinctOnly ? 'text-emerald-200 border-emerald-500/40 bg-emerald-500/10' : 'text-white/45 border-white/10 hover:border-white/25'}`}
        >
          {t('pages.threatAnalysis.inv_distinct', { defaultValue: 'Distinct only' })}
        </Button>
        <span className="w-px h-4 bg-white/10 mx-0.5" />
        <Button
          variant="unstyled"
          type="button"
          onClick={() => setCategory('')}
          className={`px-2 py-0.5 rounded text-[10px] font-mono border transition-colors ${category === '' ? 'text-cyan-200 border-cyan-500/40 bg-cyan-500/10' : 'text-white/45 border-white/10'}`}
        >
          {t('pages.threatAnalysis.inv_all', { defaultValue: 'All' })}
        </Button>
        {categories.map((c) => (
          <Button
            variant="unstyled"
            key={c}
            type="button"
            onClick={() => setCategory((p) => (p === c ? '' : c))}
            className={`px-2 py-0.5 rounded text-[10px] font-mono border transition-colors ${category === c ? 'text-cyan-200 border-cyan-500/40 bg-cyan-500/10' : 'text-white/45 border-white/10 hover:border-white/25'}`}
          >
            {c} <span className="text-white/30">{byCategory[c]}</span>
          </Button>
        ))}
      </div>

      <div className="divide-y divide-white/5 max-h-[28rem] overflow-y-auto">
        {shown.map((e) => {
          const tone = KIND_TONE[e.kind] || KIND_TONE.special
          const st = runStatus[e.id]
          const Icon = st ? STATUS_ICON[st] : null
          return (
            <div key={e.id} className="px-4 py-2 flex items-center gap-2 hover:bg-white/5">
              <span className="flex-1 min-w-0 text-[12px] font-mono text-white/85 truncate">
                {e.id}
                {e.kind === 'alias' && e.canonical && (
                  <span className="text-[10px] text-sky-300/70 ml-1.5" title={t('pages.threatAnalysis.inv_alias_hint', { defaultValue: 'Duplicate — same operation as its canonical engine' })}>→ {e.canonical}</span>
                )}
              </span>
              <span className="hidden md:block text-[10px] text-white/35 w-32 shrink-0 truncate">{e.category}</span>
              <span className={`text-[9px] px-1.5 py-0.5 rounded border shrink-0 ${tone.cls}`}>{tone.label}</span>
              {e.critical_infra && <span className="text-[9px] px-1.5 py-0.5 rounded border border-rose-500/30 bg-rose-500/10 text-rose-300 shrink-0">CI</span>}
              {Array.isArray(e.techniques) && e.techniques.length > 0 && (
                <span className="hidden lg:block text-[9px] font-mono text-white/30 w-10 text-right shrink-0" title={e.techniques.join(', ')}>{e.techniques.length}T</span>
              )}
              {Icon && <Icon className={`w-3.5 h-3.5 shrink-0 ${STATUS_TONE[st]} ${st === 'running' ? 'animate-spin' : ''}`} />}
              <Button
                variant="unstyled"
                type="button"
                onClick={() => run(e.id)}
                disabled={clientId == null || st === 'running'}
                title={clientId == null ? t('pages.threatAnalysis.inv_no_client', { defaultValue: 'Select a client to run' }) : t('pages.threatAnalysis.inv_run', { defaultValue: 'Run' })}
                className="inline-flex items-center gap-1 px-2 py-0.5 rounded text-[10px] font-medium border border-cyan-500/30 text-cyan-200 hover:bg-cyan-500/15 disabled:opacity-40 disabled:cursor-not-allowed shrink-0"
              >
                <Play className="w-3 h-3" />
                {t('pages.threatAnalysis.inv_run', { defaultValue: 'Run' })}
              </Button>
            </div>
          )
        })}
        {filtered.length > shown.length && (
          <div className="px-4 py-2 text-[10px] font-mono text-white/35">
            {t('pages.threatAnalysis.inv_more', { count: filtered.length - shown.length, defaultValue: '+{{count}} more — refine your search' })}
          </div>
        )}
        {filtered.length === 0 && (
          <div className="px-4 py-3 text-[11px] text-white/35">{t('pages.threatAnalysis.inv_none', { defaultValue: 'No engines match.' })}</div>
        )}
      </div>
    </div>
  )
}
