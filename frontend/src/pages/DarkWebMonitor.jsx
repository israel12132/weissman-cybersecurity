/**
 * Dark Web Monitor — live criminal-index war room.
 * Findings: GET /api/findings (leak_hunter, darkweb_intel, dark_web_monitor,
 * typosquatting_monitor, adversary_underground_delta).
 * Delta + source catalog: GET /api/clients/:id/underground-exposure
 * Hunt: POST /api/command-center/scan engine=adversary_underground_delta
 * Board Excel: GET /api/clients/:id/underground-exposure.xls
 */
import { useCallback, useEffect, useMemo, useState } from 'react'
import { Link } from 'react-router'
import { useTranslation } from 'react-i18next'
import { Crosshair, Eye, Search, ShieldAlert, Radio, Filter } from 'lucide-react'
import { createColumnHelper } from '@tanstack/react-table'
import PageShell from './PageShell'
import ShellScanActions from '../components/engine/ShellScanActions'
import { useFindingsWorkbench } from '../hooks/useFindingsWorkbench'
import EmptyState from '../components/ui/EmptyState'
import DataTable from '../components/ui/DataTable'
import FindingDrawer from '../components/ui/FindingDrawer'
import { SkeletonTable, SkeletonWidgetGrid } from '../components/ui/Skeleton'
import { apiFetch } from '../utils/apiFetch'
import { useVisiblePolling } from '../hooks/useVisiblePolling'
import Button from '../components/ui/Button'
import { useClient } from '../context/ClientContext'
import { firstClientTarget } from '../lib/clientTarget'
import { launchEngineScan } from '../lib/launchEngineScan'
import { useJobPoll } from '../lib/useJobPoll'

const columnHelper = createColumnHelper()

const ENGINE = 'adversary_underground_delta'

const SEVERITY_ORDER = { critical: 4, high: 3, medium: 2, low: 1, info: 0 }
const DARK_WEB_SOURCES = new Set([
  'leak_hunter',
  'darkweb_intel',
  'dark_web_monitor',
  'typosquatting_monitor',
  'adversary_underground_delta',
])

/** Typical criminal next-steps vs engines that prove them on this tenant. */
export const ADVERSARY_PLAYBOOK = [
  { mitre: 'T1597', labelKey: 'pages.darkWebMonitor.play_t1597', engines: ['adversary_underground_delta', 'darkweb_intel'] },
  { mitre: 'T1552', labelKey: 'pages.darkWebMonitor.play_t1552', engines: ['leak_hunter'] },
  { mitre: 'T1583.001', labelKey: 'pages.darkWebMonitor.play_t1583', engines: ['typosquatting_monitor', 'brand_impersonation'] },
  { mitre: 'T1078', labelKey: 'pages.darkWebMonitor.play_t1078', engines: ['credential_stuffing', 'password_spray'] },
  { mitre: 'T1190', labelKey: 'pages.darkWebMonitor.play_t1190', engines: ['bola_idor', 'jwt_attack'] },
  { mitre: 'T1486', labelKey: 'pages.darkWebMonitor.play_t1486', engines: ['threat_emulation'] },
]

export function parseUndergroundPayload(data) {
  if (!data || typeof data !== 'object') {
    return {
      added: [],
      removed: [],
      hits: [],
      findings: [],
      sources: [],
      health: [],
      current_count: 0,
      previous_count: 0,
      baseline_only: false,
      message: '',
      unavailable: false,
    }
  }
  return {
    added: Array.isArray(data.added) ? data.added : [],
    removed: Array.isArray(data.removed) ? data.removed : [],
    hits: Array.isArray(data.hits) ? data.hits : [],
    findings: Array.isArray(data.findings) ? data.findings : [],
    sources: Array.isArray(data.sources) ? data.sources : [],
    health: Array.isArray(data.health) ? data.health : [],
    current_count: Number(data.current_count) || 0,
    previous_count: Number(data.previous_count) || 0,
    baseline_only: !!data.baseline_only,
    message: data.message || '',
    unavailable: !!data.unavailable,
    current_at: data.current_at || null,
    apex: data.apex || '',
  }
}

/** hit | quiet | failed — failed only when last hunt recorded an unreachable source. */
export function sourceChipState(id, parsed) {
  const health = (parsed.health || []).find((h) => String(h.id || '').toLowerCase() === id)
  if (health) {
    if (!health.ok) return 'failed'
    if (Number(health.hit_count) > 0) return 'hit'
    return 'quiet'
  }
  const fromHits = (parsed.hits || []).some((h) => String(h.source || '').toLowerCase() === id)
  const fromSources = (parsed.sources || []).map((s) => String(s).toLowerCase()).includes(id)
  return fromHits || fromSources ? 'hit' : 'quiet'
}

export function UndergroundWarRoom({
  exposure,
  loading,
  hunting,
  onHunt,
  huntDisabled,
  playbookCoverage,
}) {
  const { t } = useTranslation()
  const parsed = parseUndergroundPayload(exposure)
  const SOURCE_IDS = ['hibp', 'ransomware_live', 'threatfox', 'urlhaus', 'urlscan']
  return (
    <div className="rounded-2xl border border-rose-500/25 bg-gradient-to-br from-rose-950/40 via-black/40 to-violet-950/30 p-4 mb-5">
      <div className="flex flex-wrap items-start justify-between gap-3 mb-3">
        <div className="min-w-0">
          <p className="text-[10px] font-mono uppercase tracking-[0.2em] text-rose-300/80">
            {t('pages.darkWebMonitor.war_title')}
          </p>
          <p className="text-[12px] text-[var(--text-tertiary)] font-mono mt-1 max-w-2xl">
            {t('pages.darkWebMonitor.war_subtitle')}
          </p>
          {parsed.message ? (
            <p className="text-[11px] text-rose-100/70 mt-2 font-mono">{parsed.message}</p>
          ) : null}
        </div>
        <Button
          variant="unstyled"
          type="button"
          onClick={onHunt}
          disabled={huntDisabled || hunting}
          className="px-4 py-2 rounded-lg text-sm font-mono font-semibold bg-rose-500/20 border border-rose-400/40 text-rose-100 hover:bg-rose-500/30 disabled:opacity-40 disabled:cursor-not-allowed transition-all"
        >
          <Crosshair className={`w-3.5 h-3.5 inline mr-1 ${hunting ? 'animate-spin' : ''}`} />
          {hunting ? t('pages.darkWebMonitor.hunting') : t('pages.darkWebMonitor.hunt')}
        </Button>
      </div>
      <div className="grid grid-cols-2 md:grid-cols-5 gap-2 mb-4">
        {SOURCE_IDS.map((id) => {
          const state = sourceChipState(id, parsed)
          const health = (parsed.health || []).find((h) => String(h.id || '').toLowerCase() === id)
          const color =
            state === 'hit' ? 'text-emerald-300' : state === 'failed' ? 'text-rose-300' : 'text-[var(--text-tertiary)]'
          const label =
            state === 'hit'
              ? t('pages.darkWebMonitor.source_hit')
              : state === 'failed'
                ? t('pages.darkWebMonitor.source_failed')
                : t('pages.darkWebMonitor.source_quiet')
          return (
            <div
              key={id}
              className="rounded-xl border border-[var(--border-default)] bg-black/30 px-3 py-2"
              title={health?.message || ''}
            >
              <div className="text-[10px] font-mono uppercase tracking-widest text-[var(--text-muted)]">{id}</div>
              <div className={`text-sm font-semibold ${color}`}>
                {loading ? '…' : label}
              </div>
            </div>
          )
        })}
      </div>
      {parsed.current_at ? (
        <p className="text-[10px] font-mono text-[var(--text-muted)] mb-3">
          {t('pages.darkWebMonitor.last_hunt', { time: new Date(parsed.current_at).toLocaleString() })}
        </p>
      ) : null}
      <div className="grid grid-cols-2 md:grid-cols-4 gap-3 mb-4">
        <KpiCard label={t('pages.darkWebMonitor.current_index')} value={parsed.current_count} />
        <KpiCard label={t('pages.darkWebMonitor.previous_index')} value={parsed.previous_count} />
        <KpiCard label={t('pages.darkWebMonitor.delta_new')} value={parsed.added.length} accent="text-rose-300" />
        <KpiCard label={t('pages.darkWebMonitor.delta_gone')} value={parsed.removed.length} accent="text-[var(--text-secondary)]" />
      </div>
      <div>
        <h3 className="text-[10px] font-mono uppercase tracking-widest text-[var(--text-muted)] mb-2">
          {t('pages.darkWebMonitor.playbook_title')}
        </h3>
        <div className="grid md:grid-cols-2 gap-2">
          {ADVERSARY_PLAYBOOK.map((row) => {
            const covered = playbookCoverage?.[row.mitre]
            return (
              <div key={row.mitre} className="flex items-center justify-between gap-2 rounded-lg border border-[var(--border-default)] px-3 py-2">
                <div>
                  <span className="text-[10px] font-mono text-rose-300/80">{row.mitre}</span>
                  <p className="text-xs text-[var(--text-secondary)]">{t(row.labelKey)}</p>
                </div>
                <span className={`text-[10px] font-mono uppercase ${covered ? 'text-emerald-300' : 'text-[var(--text-muted)]'}`}>
                  {covered ? t('pages.darkWebMonitor.play_proven') : t('pages.darkWebMonitor.play_gap')}
                </span>
              </div>
            )
          })}
        </div>
      </div>
    </div>
  )
}
const SEV_KEYS = ['critical', 'high', 'medium', 'low', 'info']

function severityBadgeClass(sev) {
  const s = (sev || 'info').toLowerCase()
  const map = {
    critical: 'text-rose-300 bg-rose-500/10 border-rose-500/40',
    high: 'text-orange-300 bg-orange-500/10 border-orange-500/40',
    medium: 'text-yellow-300 bg-yellow-500/10 border-yellow-500/40',
    low: 'text-blue-300 bg-blue-500/10 border-blue-500/40',
    info: 'text-[var(--text-secondary)] bg-[var(--bg-4)]/10 border-[var(--border-strong)]/40',
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
  const { selectedClientId, selectedClient } = useClient()
  const [findings, setFindings] = useState([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState(null)
  const [search, setSearch] = useState('')
  const [severityFilter, setSeverityFilter] = useState('all')
  const [sourceFilter, setSourceFilter] = useState('all')
  const [selected, setSelected] = useState(null)
  const [lastRefresh, setLastRefresh] = useState(null)
  const [autoRefresh, setAutoRefresh] = useState(false)
  const [exposure, setExposure] = useState(null)
  const [exposureLoading, setExposureLoading] = useState(false)
  const [hunting, setHunting] = useState(false)
  const [huntJobId, setHuntJobId] = useState(null)
  const [playbookCoverage, setPlaybookCoverage] = useState({})

  const load = useCallback(async () => {
    setError(null)
    try {
      const d = await apiFetch('/api/findings?limit=2000')
      setFindings(parseFindings(d))
      setLastRefresh(new Date())
    } catch (e) {
      setError(e.message || t('pages.darkWebMonitor.load_error', { error: '' }))
      setFindings([])
    } finally {
      setLoading(false)
    }
  }, [t])

  const loadExposure = useCallback(async (clientId) => {
    if (!clientId) {
      setExposure(null)
      return
    }
    setExposureLoading(true)
    try {
      const d = await apiFetch(`/api/clients/${clientId}/underground-exposure`)
      if (d && typeof d === 'object') setExposure(d)
    } catch (err) {
      if (import.meta.env.DEV) console.debug('underground-exposure skipped', err)
      setExposure(null)
    } finally {
      setExposureLoading(false)
    }
  }, [])

  const loadPlaybook = useCallback(async (clientId) => {
    if (!clientId) {
      setPlaybookCoverage({})
      return
    }
    try {
      const d = await apiFetch(`/api/attack-exposure/${clientId}`)
      const techniques = Array.isArray(d?.techniques) ? d.techniques : []
      const map = {}
      for (const row of ADVERSARY_PLAYBOOK) {
        map[row.mitre] = techniques.some((x) => {
          const id = String(x.id || x.technique || x.technique_id || '').toUpperCase()
          return id === row.mitre || id.startsWith(`${row.mitre}.`)
        })
      }
      setPlaybookCoverage(map)
    } catch {
      setPlaybookCoverage({})
    }
  }, [])

  useEffect(() => {
    load()
  }, [load])

  useEffect(() => {
    loadExposure(selectedClientId)
    loadPlaybook(selectedClientId)
  }, [selectedClientId, loadExposure, loadPlaybook])

  // Auto-refresh every 60s, skipping ticks while the tab is hidden.
  const pollAll = useCallback(() => {
    load()
    loadExposure(selectedClientId)
  }, [load, loadExposure, selectedClientId])
  useVisiblePolling(pollAll, 60000, { paused: !autoRefresh })

  useJobPoll(huntJobId, {
    enabled: Boolean(huntJobId),
    onComplete: async (job) => {
      setHuntJobId(null)
      setHunting(false)
      const status = String(job?.status || '').toLowerCase()
      if (status === 'failed' || status === 'dead' || status === 'cancelled') {
        setError(job?.error || job?.message || t('pages.darkWebMonitor.hunt_failed'))
      }
      await Promise.all([load(), loadExposure(selectedClientId), loadPlaybook(selectedClientId)])
    },
  })

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

  const exportExcel = async () => {
    if (!selectedClientId) return
    const r = await apiFetch(`/api/clients/${selectedClientId}/underground-exposure.xls`, { raw: true })
    const blob = await r.blob()
    const url = URL.createObjectURL(blob)
    const a = document.createElement('a')
    a.href = url
    a.download = `Weissman_underground_exposure_client_${selectedClientId}.xls`
    a.click()
    URL.revokeObjectURL(url)
  }

  const handleHunt = async () => {
    const target = firstClientTarget(selectedClient)
    if (!selectedClientId || !target) return
    setHunting(true)
    setError(null)
    try {
      const { ok, data, status } = await launchEngineScan({
        engineId: ENGINE,
        clientId: selectedClientId,
        target,
      })
      if (!ok) {
        setError(data?.detail || data?.error || t('pages.darkWebMonitor.hunt_failed_http', { status }))
        setHunting(false)
        return
      }
      const jid = data?.job_id || data?.jobId || ''
      if (jid) {
        setHuntJobId(String(jid))
        return
      }
      await Promise.all([load(), loadExposure(selectedClientId), loadPlaybook(selectedClientId)])
      setHunting(false)
    } catch (err) {
      setError(err.message || t('pages.darkWebMonitor.load_error', { error: '' }))
      setHunting(false)
    }
  }

  const handleRefresh = async () => {
    await Promise.all([load(), loadExposure(selectedClientId), loadPlaybook(selectedClientId)])
  }

  const columns = useMemo(
    () => [
      columnHelper.accessor((f) => (f.severity || 'info').toLowerCase(), {
        id: 'severity',
        header: t('pages.darkWebMonitor.col_severity'),
        cell: (ctx) => (
          <span className={severityBadgeClass(ctx.getValue())}>{String(ctx.getValue()).toUpperCase()}</span>
        ),
        sortingFn: (a, b) =>
          (SEVERITY_ORDER[a.getValue('severity')] || 0) - (SEVERITY_ORDER[b.getValue('severity')] || 0),
      }),
      columnHelper.accessor((f) => f.title || '', {
        id: 'title',
        header: t('pages.darkWebMonitor.col_title'),
        cell: (ctx) => (
          <span className="text-[var(--text-primary)] max-w-md truncate block" title={ctx.getValue()}>
            {ctx.getValue() || '—'}
          </span>
        ),
      }),
      columnHelper.accessor((f) => f.source || f.engine || '', {
        id: 'source',
        header: t('pages.darkWebMonitor.col_source'),
        cell: (ctx) => <span className="text-[var(--text-tertiary)]">{ctx.getValue() || '—'}</span>,
      }),
      columnHelper.accessor((f) => f.target || '', {
        id: 'target',
        header: t('pages.darkWebMonitor.col_target'),
        cell: (ctx) => (
          <span className="text-[var(--text-tertiary)] max-w-xs truncate block" title={ctx.getValue()}>
            {ctx.getValue() || '—'}
          </span>
        ),
      }),
      columnHelper.accessor((f) => f.discovered_at || '', {
        id: 'discovered',
        header: t('pages.darkWebMonitor.col_discovered'),
        cell: (ctx) => (
          <span className="text-[var(--text-muted)] whitespace-nowrap">
            {ctx.getValue() ? new Date(ctx.getValue()).toLocaleString() : '—'}
          </span>
        ),
      }),
    ],
    [t],
  )

  return (
    <PageShell
      title={t('pages.darkWebMonitor.title')}
      subtitle={t('pages.darkWebMonitor.subtitle')}
      badge={t('pages.darkWebMonitor.badge')}
      badgeColor="#f43f5e"
      icon={<Eye />}
      actions={(
        <div className="flex items-center gap-2 flex-wrap">
          <Button variant="unstyled"
            type="button"
            onClick={() => setAutoRefresh((v) => !v)}
            className={`px-3 py-1.5 rounded-lg border text-xs font-mono transition-colors ${
              autoRefresh
                ? 'border-emerald-500/40 text-emerald-300 bg-emerald-500/10'
                : 'border-[var(--border-default)] text-[var(--text-tertiary)] hover:text-[var(--text-secondary)]'
            }`}
          >
            <Radio className={`w-3 h-3 inline mr-1 ${autoRefresh ? 'animate-pulse' : ''}`} />
            {autoRefresh ? t('pages.darkWebMonitor.auto_on') : t('pages.darkWebMonitor.auto_off')}
          </Button>
          <ShellScanActions
            onRefresh={handleRefresh}
            onExport={exportCsv}
            refreshLoading={loading}
            exportDisabled={filtered.length === 0}
          />
          <Button variant="unstyled"
            type="button"
            onClick={exportExcel}
            disabled={!selectedClientId}
            className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-lg border border-emerald-500/35 text-[11px] font-mono text-emerald-300 hover:bg-emerald-500/10 disabled:opacity-40"
          >
            {t('pages.darkWebMonitor.export_excel')}
          </Button>
        </div>
      )}
    >
      <div className="space-y-6">
        <UndergroundWarRoom
          exposure={exposure}
          loading={exposureLoading}
          hunting={hunting}
          onHunt={handleHunt}
          huntDisabled={!selectedClientId || !firstClientTarget(selectedClient)}
          playbookCoverage={playbookCoverage}
        />
        <div className="rounded-xl border border-rose-500/20 bg-rose-950/20 px-4 py-3 flex items-start gap-3">
          <ShieldAlert className="w-4 h-4 text-rose-400 mt-0.5 shrink-0" />
          <p className="text-xs text-rose-100/70 leading-relaxed">{t('pages.darkWebMonitor.evidence_notice')}</p>
        </div>

        {lastRefresh && (
          <p className="text-[10px] font-mono text-[var(--text-disabled)]">
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
              <KpiCard label={t('pages.darkWebMonitor.low_info')} value={stats.low + stats.info} accent="text-[var(--text-secondary)]" />
            </div>

            {Object.keys(stats.bySource).length > 0 && (
              <div className="rounded-xl border border-[var(--border-default)] bg-[var(--bg-2)] p-4">
                <h3 className="text-[10px] font-mono uppercase tracking-widest text-[var(--text-muted)] mb-3">
                  {t('pages.darkWebMonitor.source_breakdown')}
                </h3>
                <div className="space-y-2">
                  {Object.entries(stats.bySource)
                    .sort((a, b) => b[1] - a[1])
                    .map(([src, count]) => (
                      <div key={src} className="flex items-center gap-3">
                        <span className="text-xs font-mono text-[var(--text-tertiary)] w-40 truncate">{src}</span>
                        <div className="flex-1 h-2 bg-[var(--row-hover-bg)] rounded-full overflow-hidden">
                          <div
                            className="h-full bg-rose-500/70 rounded-full"
                            style={{ width: `${stats.total ? (count / stats.total) * 100 : 0}%` }}
                          />
                        </div>
                        <span className="text-xs font-mono text-[var(--text-muted)] w-8 text-right">{count}</span>
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
            <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-[var(--text-disabled)]" />
            <input
              type="search"
              value={search}
              onChange={(e) => setSearch(e.target.value)}
              aria-label={t('pages.darkWebMonitor.search_placeholder')}
              placeholder={t('pages.darkWebMonitor.search_placeholder')}
              className="w-full pl-10 pr-4 py-2 rounded-xl bg-[var(--bg-2)] border border-[var(--border-default)] text-sm text-white placeholder-white/25 focus:outline-none focus:border-rose-500/40"
            />
          </div>
          <div className="flex items-center gap-1 bg-[var(--bg-2)] border border-[var(--border-default)] rounded-lg p-1 flex-wrap">
            {['all', ...SEV_KEYS].map((s) => (
              <Button variant="unstyled"
                key={s}
                type="button"
                onClick={() => setSeverityFilter(s)}
                className={`px-2.5 py-1 rounded-md text-[10px] font-mono uppercase transition-all ${
                  severityFilter === s
                    ? 'bg-rose-500/20 text-rose-300 border border-rose-500/30'
                    : 'text-[var(--text-muted)] hover:text-[var(--text-secondary)]'
                }`}
              >
                {s === 'all' ? t('pages.darkWebMonitor.filter_all') : s}
              </Button>
            ))}
          </div>
          {sources.length > 1 && (
            <select
              value={sourceFilter}
              onChange={(e) => setSourceFilter(e.target.value)}
              className="px-3 py-2 rounded-lg bg-[var(--bg-2)] border border-[var(--border-default)] text-xs text-white font-mono"
            >
              <option value="all">{t('pages.darkWebMonitor.all_sources')}</option>
              {sources.map((s) => (
                <option key={s} value={s}>{s}</option>
              ))}
            </select>
          )}
        </div>

        <section className="bg-[var(--bg-2)] border border-[var(--border-default)] rounded-xl overflow-hidden">
          <div className="flex items-center justify-between p-4 border-b border-[var(--border-default)]">
            <h3 className="text-sm font-semibold text-white flex items-center gap-2">
              <Filter className="w-4 h-4 text-rose-400" />
              {t('pages.darkWebMonitor.findings_heading')}
              <span className="text-[var(--text-muted)] font-mono text-xs">({filtered.length})</span>
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
              <p className="text-xs text-[var(--text-muted)] text-center mt-4 max-w-lg mx-auto">
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
            <DataTable
              id="darkweb-table"
              columns={columns}
              data={filtered}
              onRowClick={(row) => setSelected(row.original)}
              getRowId={(f) => f.id || f.finding_id || f.title}
              selectedRowId={selected ? selected.id || selected.finding_id || selected.title : null}
              getRowAccentColor={(f) => {
                const s = (f.severity || 'info').toLowerCase()
                return s === 'critical' ? '#f43f5e' : s === 'high' ? '#f97316' : undefined
              }}
              animateRows={false}
            />
          )}
        </section>
      </div>

      <FindingDrawer finding={selected} onClose={() => setSelected(null)} />
    </PageShell>
  )
}

function KpiCard({ label, value, accent }) {
  return (
    <div className="rounded-2xl bg-[var(--bg-2)] border border-[var(--border-default)] p-4">
      <div className="text-[10px] font-mono uppercase tracking-widest text-[var(--text-muted)]">{label}</div>
      <div className={`text-3xl font-bold mt-1 ${accent || 'text-white'}`}>{value}</div>
    </div>
  )
}
