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
import ShellScanActions from '../components/engine/ShellScanActions'
import Button from '../components/ui/Button'
import { SkeletonWidgetGrid } from '../components/ui/Skeleton'
import { apiFetch } from '../utils/apiFetch'
import { downloadCsv } from '../lib/exportFindingsCsv'
import { useToast } from '../components/ui/Toaster'
import { SEV_COLOR } from '../lib/severity'

const NS = 'pages.casbDlpCenter'
const ENGINES = ['casb_saas_posture', 'dlp_content_scan', 'cnapp_continuous', 'ai_casb_saas']

export default function CasbDlpCenter() {
  const { t } = useTranslation()
  const { toast } = useToast()
  const [findings, setFindings] = useState([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState('')
  const [searchQuery, setSearchQuery] = useState('')
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

  const filtered = useMemo(() => {
    const q = searchQuery.trim().toLowerCase()
    if (!q) return findings
    return findings.filter((f) => `${f.title} ${f.source} ${f.description}`.toLowerCase().includes(q))
  }, [findings, searchQuery])

  const liveEngineCount = useMemo(
    () => new Set(findings.map((f) => f.source || f.engine || f.type).filter(Boolean)).size,
    [findings],
  )

  const exportCsv = useCallback(() => {
    downloadCsv(
      filtered.map((f) => [f.source, f.title, f.severity, f.discovered_at]),
      ['engine', 'title', 'severity', 'discovered'],
      'weissman-casb-dlp',
    )
  }, [filtered])

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
        <ShellScanActions onRefresh={load} onExport={exportCsv} refreshLoading={loading} exportDisabled={!filtered.length} />
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
          <input
            type="search"
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
            placeholder={t(`${NS}.search_placeholder`)}
            aria-label={t(`${NS}.search_placeholder`)}
            className="w-full max-w-sm px-3 py-2 rounded-lg text-sm bg-black/40 border border-white/10 text-white"
          />
          {!filtered.length ? (
            <EmptyState title={t(`${NS}.empty_title`)} body={t(`${NS}.empty_body`)} />
          ) : (
            <ul className="space-y-2">
              {filtered.map((f) => {
                const s = (f.severity || 'info').toLowerCase()
                return (
                  <li key={f.id || f.finding_id} className="rounded-lg border border-white/10 p-3">
                    <span className="text-[10px] font-mono uppercase" style={{ color: SEV_COLOR[s] || SEV_COLOR.info }}>{s}</span>
                    <span className="ml-2 text-xs font-mono text-white/50">{f.source}</span>
                    <div className="text-sm mt-1">{f.title}</div>
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
