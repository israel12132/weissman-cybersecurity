/**
 * Control-plane of controls — live findings from fusion engines that prove installed defenses.
 */
import { useCallback, useEffect, useMemo, useState } from 'react'
import { useTranslation } from 'react-i18next'
import { ShieldCheck, Search } from 'lucide-react'
import PageShell from './PageShell'
import EmptyState from '../components/ui/EmptyState'
import EvidenceNotice from '../components/ui/EvidenceNotice'
import ExecutiveWidget from '../components/ui/ExecutiveWidget'
import ShellScanActions from '../components/engine/ShellScanActions'
import { SkeletonWidgetGrid } from '../components/ui/Skeleton'
import { apiFetch } from '../utils/apiFetch'
import { downloadCsv } from '../lib/exportFindingsCsv'
import { SEV_COLOR } from '../lib/severity'

const NS = 'pages.controlPlaneOfControls'
const ENGINES = [
  'control_plane_of_controls',
  'ot_cloud_identity_killpath',
  'bec_ato_chain',
  'ai_casb_saas',
  'dns_security_posture_fusion',
  'toxic_combo_runtime_proof',
]

export default function ControlPlaneOfControls() {
  const { t } = useTranslation()
  const [findings, setFindings] = useState([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState('')
  const [searchQuery, setSearchQuery] = useState('')

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
    return findings.filter((f) =>
      `${f.title} ${f.source} ${f.description} ${f.severity}`.toLowerCase().includes(q),
    )
  }, [findings, searchQuery])

  const exportCsv = useCallback(() => {
    downloadCsv(
      filtered.map((f) => [f.source || f.type, f.title, f.severity, f.status, f.discovered_at]),
      ['engine', 'title', 'severity', 'status', 'discovered'],
      'weissman-control-plane',
    )
  }, [filtered])

  const crit = findings.filter((f) => ['critical', 'high'].includes((f.severity || '').toLowerCase())).length

  return (
    <PageShell
      title={t(`${NS}.title`)}
      subtitle={t(`${NS}.subtitle`)}
      icon={<ShieldCheck />}
      actions={(
        <ShellScanActions onRefresh={load} onExport={exportCsv} refreshLoading={loading} exportDisabled={!filtered.length} />
      )}
    >
      <EvidenceNotice>{t(`${NS}.evidence_notice`)}</EvidenceNotice>
      {loading ? <SkeletonWidgetGrid count={3} /> : error ? (
        <EmptyState title={t(`${NS}.load_failed`)} body={error} />
      ) : (
        <div className="space-y-4">
          <div className="grid grid-cols-2 md:grid-cols-3 gap-3">
            <ExecutiveWidget label={t(`${NS}.kpi_findings`)} value={findings.length} />
            <ExecutiveWidget label={t(`${NS}.kpi_crit`)} value={crit} />
            <ExecutiveWidget label={t(`${NS}.kpi_engines`)} value={ENGINES.length} />
          </div>
          <div className="relative max-w-sm">
            <Search className="w-3.5 h-3.5 text-white/30 absolute left-2.5 top-1/2 -translate-y-1/2" />
            <input
              type="search"
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
              placeholder={t(`${NS}.search_placeholder`)}
              aria-label={t(`${NS}.search_placeholder`)}
              className="w-full pl-8 pr-3 py-2 rounded-lg text-sm bg-black/40 border border-white/10 text-white"
            />
          </div>
          {!filtered.length ? (
            <EmptyState title={t(`${NS}.empty_title`)} body={t(`${NS}.empty_body`)} />
          ) : (
            <ul className="space-y-2">
              {filtered.map((f) => {
                const s = (f.severity || 'info').toLowerCase()
                const c = SEV_COLOR[s] || SEV_COLOR.info
                return (
                  <li key={f.id || f.finding_id} className="rounded-lg border border-white/10 p-3">
                    <div className="flex gap-2 items-center">
                      <span className="text-[10px] font-mono uppercase" style={{ color: c }}>{s}</span>
                      <span className="text-xs text-white/50 font-mono">{f.source || f.type}</span>
                    </div>
                    <div className="text-sm text-white mt-1">{f.title}</div>
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
