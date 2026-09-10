/**
 * Endpoint EDR — isolate / release / quarantine via POST /api/agents/isolate.
 */
import { useCallback, useEffect, useMemo, useState } from 'react'
import { useTranslation } from 'react-i18next'
import { Laptop, Search } from 'lucide-react'
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
import { useClient } from '../context/ClientContext'

const NS = 'pages.endpointEdr'

export default function EndpointEdr() {
  const { t } = useTranslation()
  const { toast } = useToast()
  const { clients, selectedClientId } = useClient()
  const [agents, setAgents] = useState([])
  const [findings, setFindings] = useState([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState('')
  const [searchQuery, setSearchQuery] = useState('')
  const [busy, setBusy] = useState('')

  const load = useCallback(async () => {
    setLoading(true)
    setError('')
    try {
      const [a, f] = await Promise.all([
        apiFetch('/api/agents/status'),
        apiFetch('/api/findings?limit=300'),
      ])
      const list = Array.isArray(a?.agents) ? a.agents : Array.isArray(a) ? a : []
      setAgents(list)
      const all = Array.isArray(f.findings) ? f.findings : []
      setFindings(all.filter((x) => ['host_isolation', 'host_privilege_escalation', 'ebpf_sensor', 'ioc_yara_hunt'].includes(x.source || x.type)))
    } catch (e) {
      setError(e.message || t(`${NS}.load_failed`))
    } finally {
      setLoading(false)
    }
  }, [t])

  useEffect(() => { load() }, [load])

  const filtered = useMemo(() => {
    const q = searchQuery.trim().toLowerCase()
    const rows = [
      ...agents.map((ag) => ({ kind: 'agent', title: ag.hostname || ag.agent_id, id: ag.agent_id || ag.id })),
      ...findings.map((f) => ({ kind: 'finding', title: f.title, id: f.id })),
    ]
    if (!q) return rows
    return rows.filter((r) => `${r.kind} ${r.title}`.toLowerCase().includes(q))
  }, [agents, findings, searchQuery])

  const exportCsv = useCallback(() => {
    downloadCsv(
      filtered.map((r) => [r.kind, r.title, r.id]),
      ['kind', 'title', 'id'],
      'weissman-endpoint-edr',
    )
  }, [filtered])

  const act = async (action) => {
    const clientId = selectedClientId || clients?.[0]?.id
    if (!clientId) {
      toast.error(t(`${NS}.need_client`))
      return
    }
    setBusy(action)
    try {
      const d = await apiFetch('/api/agents/isolate', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ client_id: Number(clientId), action, target: 'localhost' }),
      })
      if (d?.ok === false) throw new Error(d.detail || 'isolate failed')
      toast.success(t(`${NS}.dispatched`, { action }))
      await load()
    } catch (e) {
      toast.error(e.message || t(`${NS}.dispatch_failed`))
    } finally {
      setBusy('')
    }
  }

  return (
    <PageShell
      title={t(`${NS}.title`)}
      subtitle={t(`${NS}.subtitle`)}
      icon={<Laptop />}
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
            <ExecutiveWidget label={t(`${NS}.kpi_agents`)} value={agents.length} />
            <ExecutiveWidget label={t(`${NS}.kpi_findings`)} value={findings.length} />
          </div>
          <div className="flex flex-wrap gap-2">
            {['isolate', 'release', 'quarantine', 'status'].map((a) => (
              <Button key={a} type="button" variant="ghost" disabled={!!busy} onClick={() => act(a)}>
                {busy === a ? t(`${NS}.working`) : t(`${NS}.${a}`)}
              </Button>
            ))}
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
            <ul className="space-y-1.5 text-sm">
              {filtered.map((r) => (
                <li key={`${r.kind}-${r.id}`} className="border border-white/10 rounded px-3 py-2 flex justify-between">
                  <span>{r.title}</span>
                  <span className="text-xs font-mono text-white/40">{r.kind}</span>
                </li>
              ))}
            </ul>
          )}
        </div>
      )}
    </PageShell>
  )
}
