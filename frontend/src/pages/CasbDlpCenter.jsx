/**
 * CASB / DLP / continuous CNAPP — live findings + CNAPP graph refresh.
 */
import { useCallback, useEffect, useMemo, useState } from 'react'
import { useTranslation } from 'react-i18next'
import { Cloud, Search } from 'lucide-react'
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

  const load = useCallback(async () => {
    setLoading(true)
    setError('')
    try {
      const d = await apiFetch('/api/findings?limit=500')
      if (d?.ok === false) throw new Error(d.detail || 'load failed')
      const all = Array.isArray(d.findings) ? d.findings : []
      setFindings(all.filter((f) => ENGINES.includes(f.source || f.type || f.engine)))
    } catch (e) {
      setError(e.message || t(`${NS}.load_failed`))
    } finally {
      setLoading(false)
    }
  }, [t])

  useEffect(() => { load() }, [load])

  const filtered = useMemo(() => {
    const q = searchQuery.trim().toLowerCase()
    if (!q) return findings
    return findings.filter((f) => `${f.title} ${f.source} ${f.description}`.toLowerCase().includes(q))
  }, [findings, searchQuery])

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
      if (d?.ok === false) throw new Error(d.detail || 'refresh failed')
      toast.success(t(`${NS}.refreshed`, { n: d.jobs_queued ?? 0 }))
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
        <EmptyState title={t(`${NS}.load_failed`)} body={error} />
      ) : (
        <div className="space-y-4">
          <div className="grid grid-cols-2 gap-3">
            <ExecutiveWidget label={t(`${NS}.kpi_findings`)} value={findings.length} />
            <ExecutiveWidget label={t(`${NS}.kpi_engines`)} value={ENGINES.length} />
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
