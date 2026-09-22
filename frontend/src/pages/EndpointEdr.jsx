/**
 * Endpoint EDR — isolate / release / quarantine via POST /api/agents/isolate.
 */
import { useCallback, useEffect, useMemo, useState } from 'react'
import { useTranslation } from 'react-i18next'
import { Laptop } from 'lucide-react'
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
  const [kindFilter, setKindFilter] = useState('all')
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

  const allRows = useMemo(
    () => [
      ...agents.map((ag) => ({ kind: 'agent', title: ag.hostname || ag.agent_id, id: ag.agent_id || ag.id })),
      ...findings.map((f) => ({ kind: 'finding', title: f.title, id: f.id })),
    ],
    [agents, findings],
  )

  const filtered = useMemo(() => {
    const q = searchQuery.trim().toLowerCase()
    return allRows.filter((r) => {
      if (kindFilter !== 'all' && r.kind !== kindFilter) return false
      if (!q) return true
      return `${r.kind} ${r.title}`.toLowerCase().includes(q)
    })
  }, [allRows, searchQuery, kindFilter])

  const kindPills = useMemo(
    () =>
      [
        { id: 'all', label: t(`${NS}.filter_all`), count: allRows.length, color: '#22d3ee' },
        { id: 'agent', label: t(`${NS}.filter_agents`), count: agents.length, color: '#4ade80' },
        { id: 'finding', label: t(`${NS}.filter_findings`), count: findings.length, color: '#fb923c' },
      ].map((p) => ({ ...p, active: kindFilter === p.id, onClick: () => setKindFilter(p.id) })),
    [allRows.length, agents.length, findings.length, kindFilter, t],
  )

  const exportCsv = useCallback(() => {
    if (error) return
    downloadCsv(
      filtered.map((r) => [r.kind, r.title, r.id]),
      ['kind', 'title', 'id'],
      'weissman-endpoint-edr',
    )
  }, [error, filtered])

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
        <ShellScanActions onRefresh={load} onExport={error ? undefined : exportCsv} refreshLoading={loading} exportDisabled={!!error || !filtered.length} />
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
          <div className="flex flex-wrap items-end gap-4">
            <input
              type="search"
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
              placeholder={t(`${NS}.search_placeholder`)}
              aria-label={t(`${NS}.search_placeholder`)}
              className="w-full max-w-sm px-3 py-2 rounded-lg text-sm bg-[var(--bg-3)] border border-[var(--border-default)] text-[var(--text-primary)] placeholder-[var(--text-muted)] focus:outline-none focus:border-cyan-500/40"
            />
            {allRows.length > 0 && <FilterPills pills={kindPills} />}
          </div>
          {!filtered.length ? (
            <EmptyState title={t(`${NS}.empty_title`)} body={t(`${NS}.empty_body`)} />
          ) : (
            <ul className="space-y-1.5 text-sm">
              {filtered.map((r, i) => (
                <li
                  key={`${r.kind}-${r.id ?? i}`}
                  className="border border-[var(--border-default)] bg-[var(--table-surface)] rounded-lg px-3 py-2 flex items-center justify-between gap-3"
                >
                  <span className="text-[var(--text-primary)] truncate" title={r.title}>{r.title || '—'}</span>
                  <span
                    className="text-[10px] font-mono uppercase tracking-wider px-1.5 py-0.5 rounded border shrink-0"
                    style={
                      r.kind === 'agent'
                        ? { color: '#4ade80', borderColor: '#4ade8055' }
                        : { color: '#fb923c', borderColor: '#fb923c55' }
                    }
                  >
                    {t(`${NS}.kind_${r.kind}`)}
                  </span>
                </li>
              ))}
            </ul>
          )}
        </div>
      )}
    </PageShell>
  )
}
