/**
 * CASB / DLP / continuous CNAPP — live findings + CNAPP graph refresh.
 */
import { useCallback, useEffect, useMemo, useRef, useState } from 'react'
import { useTranslation } from 'react-i18next'
import { Cloud } from 'lucide-react'
import PageShell from './PageShell'
import EmptyState from '../components/ui/EmptyState'
import EvidenceNotice from '../components/ui/EvidenceNotice'
import ExecutiveWidget from '../components/ui/ExecutiveWidget'
import FilterPills from '../components/ui/FilterPills'
import ShellScanActions from '../components/engine/ShellScanActions'
import Button from '../components/ui/Button'
import { SkeletonWidgetGrid } from '../components/ui/Skeleton'
import { apiFetch } from '../utils/apiFetch'
import { downloadCsv } from '../lib/exportFindingsCsv'
import { useToast } from '../components/ui/Toaster'
import { SEV_COLOR, normalizeSeverity } from '../lib/severity'

const NS = 'pages.casbDlpCenter'
const ENGINES = ['casb_saas_posture', 'dlp_content_scan', 'cnapp_continuous', 'ai_casb_saas']
const SEV_KEYS = ['critical', 'high', 'medium', 'low', 'info']

export default function CasbDlpCenter() {
  const { t } = useTranslation()
  const { toast } = useToast()
  const [findings, setFindings] = useState([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState('')
  const [searchQuery, setSearchQuery] = useState('')
  const [sevFilter, setSevFilter] = useState('all')
  const [refreshing, setRefreshing] = useState(false)
  const abortRef = useRef(null)

  const load = useCallback(async () => {
    abortRef.current?.abort()
    const ac = new AbortController()
    abortRef.current = ac
    setLoading(true)
    setError('')
    try {
      const d = await apiFetch('/api/findings?limit=500', { signal: ac.signal })
      if (d?.ok === false || d?.unavailable) {
        throw new Error(d.detail || 'findings unavailable')
      }
      const all = Array.isArray(d) ? d : (Array.isArray(d.findings) ? d.findings : [])
      if (ac.signal.aborted) return
      setFindings(all.filter((f) => ENGINES.includes(f.source || f.type || f.engine)))
    } catch (e) {
      if (e?.name === 'AbortError' || ac.signal.aborted) return
      setFindings([])
      setError(e.message || 'load failed')
    } finally {
      if (abortRef.current === ac && !ac.signal.aborted) setLoading(false)
    }
  }, [])

  useEffect(() => {
    load()
    return () => abortRef.current?.abort()
  }, [load])

  const sevCounts = useMemo(() => {
    const c = { all: findings.length, critical: 0, high: 0, medium: 0, low: 0, info: 0 }
    for (const f of findings) c[normalizeSeverity(f.severity)] += 1
    return c
  }, [findings])

  const filtered = useMemo(() => {
    const q = searchQuery.trim().toLowerCase()
    return findings.filter((f) => {
      if (sevFilter !== 'all' && normalizeSeverity(f.severity) !== sevFilter) return false
      if (!q) return true
      return `${f.title} ${f.source} ${f.description}`.toLowerCase().includes(q)
    })
  }, [findings, searchQuery, sevFilter])

  const sevPills = useMemo(
    () =>
      [
        { id: 'all', label: t('common.all'), count: sevCounts.all, color: '#22d3ee' },
        ...SEV_KEYS.filter((s) => sevCounts[s] > 0).map((s) => ({
          id: s,
          label: t(`severity.${s}`),
          count: sevCounts[s],
          color: SEV_COLOR[s] || SEV_COLOR.info,
        })),
      ].map((p) => ({ ...p, active: sevFilter === p.id, onClick: () => setSevFilter(p.id) })),
    [sevCounts, sevFilter, t],
  )

  const liveEngineCount = useMemo(
    () => new Set(findings.map((f) => f.source || f.engine || f.type).filter(Boolean)).size,
    [findings],
  )

  const exportCsv = useCallback(() => {
    if (error) return
    downloadCsv(
      filtered.map((f) => [f.source, f.title, f.severity, f.discovered_at]),
      ['engine', 'title', 'severity', 'discovered'],
      'weissman-casb-dlp',
    )
  }, [error, filtered])

  const refreshGraph = async () => {
    setRefreshing(true)
    try {
      const d = await apiFetch('/api/cnapp/refresh', { method: 'POST' })
      if (d?.ok === false || d?.unavailable || d.jobs_queued == null) {
        throw new Error(d.detail || t(`${NS}.refresh_failed`))
      }
      toast.success(t(`${NS}.refreshed`, { n: d.jobs_queued }))
      await load()
    } catch (e) {
      toast.error(e.message || t(`${NS}.refresh_failed`))
    } finally {
      setRefreshing(false)
    }
  }

  return (
    <PageShell
      title={t(`${NS}.title`)}
      subtitle={t(`${NS}.subtitle`)}
      icon={<Cloud />}
      actions={(
        <ShellScanActions onRefresh={load} onExport={error ? undefined : exportCsv} refreshLoading={loading} exportDisabled={!!error || !filtered.length} />
      )}
    >
      <EvidenceNotice>{t(`${NS}.evidence_notice`)}</EvidenceNotice>
      {loading ? <SkeletonWidgetGrid count={3} /> : error ? (
        <p className="text-sm text-amber-200/90" data-testid="casb-dlp-unavailable" role="alert">
          {t(`${NS}.unavailable`)}
        </p>
      ) : (
        <div className="space-y-4">
          <div className="grid grid-cols-2 gap-3">
            <ExecutiveWidget label={t(`${NS}.kpi_findings`)} value={findings.length} />
            <ExecutiveWidget label={t(`${NS}.kpi_engines`)} value={findings.length ? liveEngineCount : '—'} />
          </div>
          <Button type="button" onClick={refreshGraph} disabled={refreshing}>
            {refreshing ? t(`${NS}.refreshing`) : t(`${NS}.refresh_graph`)}
          </Button>
          <div className="flex flex-wrap items-end gap-4">
            <input
              type="search"
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
              placeholder={t(`${NS}.search_placeholder`)}
              aria-label={t(`${NS}.search_placeholder`)}
              className="w-full max-w-sm px-3 py-2 rounded-lg text-sm bg-[var(--bg-3)] border border-[var(--border-default)] text-[var(--text-primary)] placeholder-[var(--text-muted)] focus:outline-none focus:border-cyan-500/40"
            />
            {findings.length > 0 && <FilterPills pills={sevPills} />}
          </div>
          {!filtered.length ? (
            <EmptyState title={t(`${NS}.empty_title`)} body={t(`${NS}.empty_body`)} />
          ) : (
            <ul className="space-y-2">
              {filtered.map((f) => {
                const s = normalizeSeverity(f.severity)
                return (
                  <li key={f.id || f.finding_id} className="rounded-lg border border-[var(--border-default)] bg-[var(--table-surface)] p-3">
                    <span className="text-[10px] font-mono uppercase tracking-wider" style={{ color: SEV_COLOR[s] || SEV_COLOR.info }}>{t(`severity.${s}`)}</span>
                    <span className="ml-2 text-xs font-mono text-[var(--text-muted)]">{f.source}</span>
                    <div className="text-sm mt-1 text-[var(--text-primary)]">{f.title}</div>
                  </li>
                )
              })}
            </ul>
          )}
        </div>
      )}
    </PageShell>
  )
}
