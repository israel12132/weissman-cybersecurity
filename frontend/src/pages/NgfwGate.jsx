/**
 * Weissman Gate — vNGFW / ZTNA / detonation farm control plane (fails visibly when down).
 */
import { useCallback, useEffect, useMemo, useState } from 'react'
import { useTranslation } from 'react-i18next'
import { Shield } from 'lucide-react'
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

const NS = 'pages.ngfwGate'

export default function NgfwGate() {
  const { t } = useTranslation()
  const { toast } = useToast()
  const [status, setStatus] = useState(null)
  const [findings, setFindings] = useState([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState('')
  const [searchQuery, setSearchQuery] = useState('')
  const [policyText, setPolicyText] = useState('{"default_action":"allow","rules":[]}')
  const [applying, setApplying] = useState(false)

  const load = useCallback(async () => {
    setLoading(true)
    setError('')
    try {
      const [st, f] = await Promise.all([
        apiFetch('/api/vngfw/status'),
        apiFetch('/api/findings?limit=300'),
      ])
      if (st?.ok === false && st.dataplane_live == null) throw new Error(st.detail || 'status failed')
      setStatus(st)
      if (st?.policy) setPolicyText(JSON.stringify(st.policy, null, 2))
      const all = Array.isArray(f.findings) ? f.findings : []
      setFindings(all.filter((x) => ['ngfw_posture', 'weissman_vngfw', 'malware_detonation', 'sase_security_bypass', 'zero_trust_bypass'].includes(x.source || x.type)))
    } catch (e) {
      setError(e.message || t(`${NS}.load_failed`))
    } finally {
      setLoading(false)
    }
  }, [t])

  useEffect(() => { load() }, [load])

  const filtered = useMemo(() => {
    const q = searchQuery.trim().toLowerCase()
    const hay = [
      ...(findings || []),
      { title: status?.note, source: 'dataplane', severity: status?.dataplane_live ? 'info' : 'high' },
    ]
    if (!q) return hay
    return hay.filter((x) => `${x.title} ${x.source} ${x.note || ''}`.toLowerCase().includes(q))
  }, [findings, searchQuery, status])

  const exportCsv = useCallback(() => {
    downloadCsv(
      filtered.map((x) => [x.source, x.title, x.severity, status?.dataplane_live]),
      ['engine', 'title', 'severity', 'dataplane_live'],
      'weissman-gate',
    )
  }, [filtered, status])

  const savePolicy = async () => {
    try {
      const policy = JSON.parse(policyText)
      const d = await apiFetch('/api/vngfw/policy', {
        method: 'PUT',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(policy),
      })
      if (d?.ok === false) throw new Error(d.detail || 'save failed')
      toast.success(t(`${NS}.policy_saved`))
      await load()
    } catch (e) {
      toast.error(e.message || t(`${NS}.policy_failed`))
    }
  }

  const applyDataplane = async () => {
    setApplying(true)
    try {
      const d = await apiFetch('/api/vngfw/apply', { method: 'POST' })
      if (d?.ok === false) throw new Error(d.detail || t(`${NS}.apply_failed`))
      toast.success(d.detail || t(`${NS}.apply_ok`))
      await load()
    } catch (e) {
      toast.error(e.message || t(`${NS}.apply_failed`))
    } finally {
      setApplying(false)
    }
  }

  const live = Boolean(status?.dataplane_live)

  return (
    <PageShell
      title={t(`${NS}.title`)}
      subtitle={t(`${NS}.subtitle`)}
      icon={<Shield />}
      actions={(
        <ShellScanActions onRefresh={load} onExport={exportCsv} refreshLoading={loading} exportDisabled={!filtered.length} />
      )}
    >
      <EvidenceNotice>{t(`${NS}.evidence_notice`)}</EvidenceNotice>
      {loading ? <SkeletonWidgetGrid count={3} /> : error ? (
        <EmptyState title={t(`${NS}.load_failed`)} body={error} />
      ) : (
        <div className="space-y-4">
          <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
            <ExecutiveWidget label={t(`${NS}.kpi_live`)} value={live ? t(`${NS}.up`) : t(`${NS}.down`)} />
            <ExecutiveWidget label={t(`${NS}.kpi_nft`)} value={status?.nft_table_weissman_gate ? t(`${NS}.yes`) : t(`${NS}.no`)} />
            <ExecutiveWidget label={t(`${NS}.kpi_ztna`)} value={status?.ztna?.ok ? t(`${NS}.up`) : t(`${NS}.down`)} />
            <ExecutiveWidget label={t(`${NS}.kpi_farm`)} value={status?.detonation?.ok ? t(`${NS}.up`) : t(`${NS}.down`)} />
          </div>
          <p className="text-sm text-amber-200/90">{status?.note}</p>
          <pre className="text-[10px] font-mono whitespace-pre-wrap bg-black/40 border border-white/10 rounded-lg p-3 max-h-40 overflow-auto">
            {status?.nft_preview || ''}
          </pre>
          <label className="block text-xs text-white/50">{t(`${NS}.policy_label`)}
            <textarea
              value={policyText}
              onChange={(e) => setPolicyText(e.target.value)}
              rows={8}
              className="mt-1 w-full font-mono text-xs bg-black/40 border border-white/10 rounded-lg p-2 text-white"
            />
          </label>
          <div className="flex flex-wrap gap-2">
            <Button type="button" onClick={savePolicy}>{t(`${NS}.save_policy`)}</Button>
            <Button type="button" onClick={applyDataplane} disabled={applying}>
              {applying ? t(`${NS}.applying`) : t(`${NS}.apply_dataplane`)}
            </Button>
          </div>
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
            <ul className="space-y-2 text-sm">
              {filtered.map((x, i) => (
                <li key={x.id || x.finding_id || i} className="border border-white/10 rounded-lg p-3">
                  <span className="text-xs font-mono text-white/40">{x.source}</span>
                  <div>{x.title}</div>
                </li>
              ))}
            </ul>
          )}
        </div>
      )}
    </PageShell>
  )
}
