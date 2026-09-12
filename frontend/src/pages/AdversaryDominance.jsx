/**
 * Adversary Dominance — live credential→ransomware fusion + board pack downloads.
 * Findings from GET /api/findings only. Scan: POST /api/command-center/scan engine=credential_ransomware_fusion.
 */
import { useCallback, useEffect, useMemo, useState } from 'react'
import { Link } from 'react-router'
import { useTranslation } from 'react-i18next'
import { ShieldAlert, Search, Activity } from 'lucide-react'
import { createColumnHelper } from '@tanstack/react-table'
import PageShell from './PageShell'
import ShellScanActions from '../components/engine/ShellScanActions'
import ClientReportDownloadBar from '../components/ClientReportDownloadBar'
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
import { useCommandCenterScan } from '../hooks/useCommandCenterScan'
import { useJobPoll, extractFindingsFromJob } from '../lib/useJobPoll'

const columnHelper = createColumnHelper()
const SEVERITY_ORDER = { critical: 4, high: 3, medium: 2, low: 1, info: 0 }
const FUSION_SOURCES = new Set([
  'credential_ransomware_fusion',
  'leak_hunter',
  'darkweb_intel',
  'dark_web_monitor',
  'threat_intel_fusion',
  'typosquatting_monitor',
])
const SEV_KEYS = ['critical', 'high', 'medium', 'low', 'info']
const NS = 'pages.adversaryDominance'

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
    .filter((f) => FUSION_SOURCES.has((f.source || f.engine || f.type || '').toLowerCase()))
    .sort(
      (a, b) =>
        (SEVERITY_ORDER[(b.severity || '').toLowerCase()] || 0)
        - (SEVERITY_ORDER[(a.severity || '').toLowerCase()] || 0),
    )
}

function findingBlob(f) {
  return `${f.title || ''} ${f.description || ''} ${f.proof || ''} ${f.source || ''} ${f.kill_chain || ''}`.toLowerCase()
}

function feedHits(findings) {
  const blob = findings.map(findingBlob).join(' ')
  return {
    kev: /cisa kev|known exploited/.test(blob),
    hibp: /hibp|haveibeenpwned|have i been pwned/.test(blob),
    urlhaus: /urlhaus/.test(blob),
    intelx: /intelx|intelligence x/.test(blob),
  }
}

export default function AdversaryDominance() {
  const { t } = useTranslation()
  const { selectedClientId, selectedClient } = useClient()
  const { postScan } = useCommandCenterScan(selectedClientId)
  const [findings, setFindings] = useState([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState(null)
  const [search, setSearch] = useState('')
  const [severityFilter, setSeverityFilter] = useState('all')
  const [selected, setSelected] = useState(null)
  const [lastRefresh, setLastRefresh] = useState(null)
  const [autoRefresh, setAutoRefresh] = useState(false)
  const [jobId, setJobId] = useState(null)
  const [jobStatus, setJobStatus] = useState('')
  const [running, setRunning] = useState(false)
  const [nerve, setNerve] = useState(null)

  const load = useCallback(async () => {
    setError(null)
    try {
      const q = selectedClientId ? `&client_id=${selectedClientId}` : ''
      const d = await apiFetch(`/api/findings?limit=2000${q}`)
      setFindings(parseFindings(d))
      setLastRefresh(new Date())
    } catch (e) {
      setError(e.message || t(`${NS}.load_error`, { error: '' }))
      setFindings([])
    } finally {
      setLoading(false)
    }
  }, [t, selectedClientId])

  useEffect(() => {
    load()
  }, [load])

  useEffect(() => {
    let cancelled = false
    apiFetch('/api/first-mover/nerve')
      .then((d) => {
        if (!cancelled && d && typeof d === 'object') setNerve(d)
      })
      .catch(() => {
        if (!cancelled) setNerve(null)
      })
    return () => {
      cancelled = true
    }
  }, [])

  useVisiblePolling(load, 60000, { paused: !autoRefresh })

  useJobPoll(jobId, {
    enabled: !!jobId,
    onUpdate: (job) => setJobStatus(job?.status || ''),
    onComplete: (job) => {
      setRunning(false)
      setJobStatus(job?.status || 'completed')
      const extra = parseFindings(extractFindingsFromJob(job))
      if (extra.length) {
        setFindings((prev) => {
          const seen = new Set(prev.map((f) => f.id || f.title))
          const merged = [...extra.filter((f) => !seen.has(f.id || f.title)), ...prev]
          return merged
        })
      }
      load()
    },
  })

  const filtered = useMemo(() => {
    const q = search.trim().toLowerCase()
    return findings.filter((f) => {
      const sev = (f.severity || 'info').toLowerCase()
      if (severityFilter !== 'all' && sev !== severityFilter) return false
      if (!q) return true
      const hay = `${f.title || ''} ${f.description || ''} ${f.target || ''} ${f.source || ''}`.toLowerCase()
      return hay.includes(q)
    })
  }, [findings, search, severityFilter])

  const stats = useMemo(() => {
    const by = Object.fromEntries(SEV_KEYS.map((k) => [k, 0]))
    for (const f of findings) {
      const s = (f.severity || 'info').toLowerCase()
      if (by[s] !== undefined) by[s] += 1
    }
    return { ...by, total: findings.length }
  }, [findings])

  const feeds = useMemo(() => feedHits(findings), [findings])
  const fusionNerve = nerve?.fusion?.credential_ransomware || {}

  const { exportCsv: exportWorkbenchCsv } = useFindingsWorkbench(filtered, { csvPrefix: 'adversary-dominance' })

  const columns = useMemo(
    () => [
      columnHelper.accessor((f) => (f.severity || 'info').toLowerCase(), {
        id: 'severity',
        header: t(`${NS}.col_severity`),
        cell: (ctx) => <span className={severityBadgeClass(ctx.getValue())}>{String(ctx.getValue()).toUpperCase()}</span>,
      }),
      columnHelper.accessor((f) => f.title || '', {
        id: 'title',
        header: t(`${NS}.col_title`),
        cell: (ctx) => (
          <span className="text-[var(--text-primary)] max-w-md truncate block" title={ctx.getValue()}>
            {ctx.getValue() || '—'}
          </span>
        ),
      }),
      columnHelper.accessor((f) => f.source || f.engine || '', {
        id: 'source',
        header: t(`${NS}.col_source`),
        cell: (ctx) => <span className="text-[var(--text-tertiary)]">{ctx.getValue() || '—'}</span>,
      }),
      columnHelper.accessor((f) => f.target || '', {
        id: 'target',
        header: t(`${NS}.col_target`),
        cell: (ctx) => (
          <span className="text-[var(--text-tertiary)] max-w-xs truncate block" title={ctx.getValue()}>
            {ctx.getValue() || '—'}
          </span>
        ),
      }),
    ],
    [t],
  )

  async function runFusion() {
    const target = firstClientTarget(selectedClient)
    if (!selectedClientId || !target) {
      setError(t(`${NS}.need_client`))
      return
    }
    setRunning(true)
    setError(null)
    try {
      const r = await postScan({
        engine: 'credential_ransomware_fusion',
        target,
        client_id: selectedClientId,
      })
      if (!r.ok) {
        setError(r.data?.error || r.data?.detail || t(`${NS}.scan_failed`))
        setRunning(false)
        return
      }
      const id = r.data?.job_id || r.data?.id
      if (id) {
        setJobId(id)
        setJobStatus('queued')
      } else {
        setRunning(false)
        load()
      }
    } catch (e) {
      setError(e.message || t(`${NS}.scan_failed`))
      setRunning(false)
    }
  }

  return (
    <PageShell
      title={t(`${NS}.title`)}
      subtitle={t(`${NS}.subtitle`)}
      badge={t(`${NS}.badge`)}
      badgeColor="#f43f5e"
      icon={<ShieldAlert />}
      actions={(
        <div className="flex items-center gap-2 flex-wrap">
          <Button
            variant="unstyled"
            type="button"
            onClick={runFusion}
            disabled={running}
            className="px-4 py-2 rounded-xl text-[11px] font-mono border border-rose-500/40 bg-rose-500/15 text-rose-100 hover:bg-rose-500/25 disabled:opacity-50"
          >
            {running ? t(`${NS}.scanning`) : t(`${NS}.run_fusion`)}
          </Button>
          <ShellScanActions
            onRefresh={load}
            onExport={() => filtered.length && exportWorkbenchCsv()}
            refreshLoading={loading}
            exportDisabled={!filtered.length}
          />
        </div>
      )}
    >
      <div className="space-y-4">
        {selectedClientId && <ClientReportDownloadBar clientId={selectedClientId} />}
        {jobStatus && (
          <p className="text-[11px] font-mono text-[var(--text-tertiary)]">
            {t(`${NS}.job_status`, { status: jobStatus })}
          </p>
        )}
        {error && (
          <div className="rounded-xl border border-rose-500/40 bg-rose-950/30 px-4 py-3 text-sm text-rose-200" role="alert">
            {error}
          </div>
        )}
        {loading ? (
          <>
            <SkeletonWidgetGrid />
            <SkeletonTable />
          </>
        ) : (
          <>
            <div className="grid grid-cols-2 md:grid-cols-5 gap-3">
              {['total', ...SEV_KEYS].map((k) => (
                <div key={k} className="rounded-xl border border-white/10 bg-black/30 px-3 py-2">
                  <div className="text-[10px] font-mono uppercase tracking-wider text-white/40">{t(`${NS}.${k === 'total' ? 'total_hits' : k}`)}</div>
                  <div className="text-lg font-semibold text-white">{k === 'total' ? stats.total : stats[k]}</div>
                </div>
              ))}
            </div>
            <div className="rounded-xl border border-rose-500/20 bg-rose-950/20 px-4 py-3" aria-label={t(`${NS}.feed_legend`)}>
              <div className="flex items-center gap-2 mb-2 text-[10px] font-mono uppercase tracking-wider text-rose-200/70">
                <Activity className="w-3.5 h-3.5" aria-hidden />
                {t(`${NS}.feed_legend`)}
              </div>
              <div className="flex flex-wrap gap-2">
                {[
                  { id: 'kev', hit: feeds.kev, keyOn: true },
                  { id: 'hibp', hit: feeds.hibp, keyOn: fusionNerve.hibp_pro_key },
                  { id: 'urlhaus', hit: feeds.urlhaus, keyOn: true },
                  { id: 'intelx', hit: feeds.intelx, keyOn: fusionNerve.intelx_key },
                ].map((f) => (
                  <span
                    key={f.id}
                    className={`inline-flex items-center gap-1.5 px-2.5 py-1 rounded-full text-[10px] font-mono border ${
                      f.hit
                        ? 'border-emerald-400/50 bg-emerald-500/15 text-emerald-100'
                        : 'border-white/10 bg-black/40 text-white/45'
                    }`}
                  >
                    <span
                      className={`h-1.5 w-1.5 rounded-full ${f.hit ? 'bg-emerald-400 animate-pulse' : f.keyOn ? 'bg-amber-400' : 'bg-white/25'}`}
                      aria-hidden
                    />
                    {t(`${NS}.feed_${f.id}`)}
                    {' · '}
                    {f.hit ? t(`${NS}.feed_hit`) : f.keyOn ? t(`${NS}.feed_armed`) : t(`${NS}.feed_silent`)}
                  </span>
                ))}
              </div>
            </div>
            <div className="flex flex-wrap gap-2 items-center">
              <div className="relative flex-1 min-w-[200px]">
                <Search className="absolute left-2 top-2.5 w-4 h-4 text-white/30" />
                <input
                  type="search"
                  value={search}
                  onChange={(e) => setSearch(e.target.value)}
                  placeholder={t(`${NS}.search_placeholder`)}
                  className="w-full pl-8 pr-3 py-2 rounded-xl bg-black/40 border border-white/10 text-sm text-white"
                />
              </div>
              <select
                value={severityFilter}
                onChange={(e) => setSeverityFilter(e.target.value)}
                className="px-3 py-2 rounded-xl bg-black/40 border border-white/10 text-sm text-white"
              >
                <option value="all">{t(`${NS}.filter_all`)}</option>
                {SEV_KEYS.map((k) => (
                  <option key={k} value={k}>{k}</option>
                ))}
              </select>
              <Link to="/dark-web" className="text-xs font-mono text-violet-300 hover:underline">
                {t(`${NS}.open_dark_web`)}
              </Link>
              {selectedClientId && (
                <Link
                  to={`/attack-surface-graph/${selectedClientId}`}
                  className="text-xs font-mono text-cyan-300 hover:underline"
                >
                  {t(`${NS}.open_graph`)}
                </Link>
              )}
            </div>
            {filtered.length === 0 ? (
              <EmptyState
                title={t(`${NS}.empty_title`)}
                body={t(`${NS}.empty_body`)}
              />
            ) : (
              <DataTable
                id="adversary-dominance-table"
                columns={columns}
                data={filtered}
                getRowId={(f) => f.id || f.finding_id || f.title}
                onRowClick={(row) => setSelected(row.original)}
              />
            )}
            {lastRefresh && (
              <p className="text-[10px] font-mono text-white/30">
                {t(`${NS}.last_updated`, { time: lastRefresh.toLocaleString() })}
              </p>
            )}
            <Button
              variant="unstyled"
              type="button"
              onClick={() => setAutoRefresh((v) => !v)}
              className="text-[11px] font-mono text-cyan-300"
            >
              {autoRefresh ? t(`${NS}.auto_on`) : t(`${NS}.auto_off`)}
            </Button>
          </>
        )}
        <FindingDrawer finding={selected} onClose={() => setSelected(null)} />
      </div>
    </PageShell>
  )
}
