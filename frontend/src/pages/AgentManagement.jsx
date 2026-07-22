import { useCallback, useEffect, useMemo, useState } from 'react'
import { Link } from 'react-router-dom'
import { useTranslation } from 'react-i18next'
import { Server, Radio, Zap } from 'lucide-react'
import { createColumnHelper } from '@tanstack/react-table'
import PageShell from './PageShell'
import ShellScanActions from '../components/engine/ShellScanActions'
import WeissmanListToolbar from '../components/engine/WeissmanListToolbar'
import { useFindingsWorkbench } from '../hooks/useFindingsWorkbench'
import EmptyState from '../components/ui/EmptyState'
import DataTable from '../components/ui/DataTable'
import CopyButton from '../components/ui/CopyButton'
import { SkeletonTable, SkeletonWidgetGrid } from '../components/ui/Skeleton'
import { apiFetch } from '../utils/apiFetch'
import { apiUrl } from '../lib/apiBase'
import { useVisiblePolling } from '../hooks/useVisiblePolling'
import Button from '../components/ui/Button'
import { useApiQuery } from '../hooks/useApiQuery'

const columnHelper = createColumnHelper()

function timeAgo(iso, t) {
  if (!iso) return t('agents.never_seen')
  const ms = Date.now() - new Date(iso).getTime()
  if (Number.isNaN(ms)) return t('agents.unknown')
  const s = Math.max(1, Math.floor(ms / 1000))
  if (s < 60) return t('agents.time_seconds', { count: s })
  if (s < 3600) return t('agents.time_minutes', { count: Math.floor(s / 60) })
  if (s < 86400) return t('agents.time_hours', { count: Math.floor(s / 3600) })
  return t('agents.time_days', { count: Math.floor(s / 86400) })
}

function StatusBadge({ online, last_seen_at, t }) {
  if (online) {
    return (
      <span className="text-[10px] font-mono px-2 py-0.5 rounded border border-emerald-500/40 bg-emerald-500/15 text-emerald-300">
        {t('agents.status_online')}
      </span>
    )
  }
  if (!last_seen_at) {
    return (
      <span className="text-[10px] font-mono px-2 py-0.5 rounded border border-[var(--border-strong)] text-[var(--text-muted)]">
        {t('agents.status_never')}
      </span>
    )
  }
  return (
    <span className="text-[10px] font-mono px-2 py-0.5 rounded border border-rose-500/40 bg-rose-500/10 text-rose-300">
      {t('agents.status_offline')}
    </span>
  )
}

export default function AgentManagement() {
  const { t } = useTranslation()
  const [agents, setAgents] = useState([])
  const [fleetBusy, setFleetBusy] = useState(false)
  const [loading, setLoading] = useState(true)
  // Server-state via the shared TanStack Query hook (dedup + cache + retry) instead of a
  // hand-rolled useEffect fetch — reference for migrating the other dashboards.
  const { data: clients = [] } = useApiQuery(['clients'], '/api/clients', {
    transform: (d) => (Array.isArray(d) ? d : []),
  })
  const [tokenClient, setTokenClient] = useState('')
  const [tokenValidity, setTokenValidity] = useState(60)
  const [generatedToken, setGeneratedToken] = useState(null)
  const [err, setErr] = useState(null)
  // Errors from user actions (token/dispatch) are kept separate from the agent-list
  // fetch error so the 15s auto-refresh can't silently clear an action's banner.
  const [actionErr, setActionErr] = useState(null)
  const [selectedAgent, setSelectedAgent] = useState(null)
  const [statusFilter, setStatusFilter] = useState('all')
  const [autoRefresh, setAutoRefresh] = useState(true)

  const refresh = useCallback(async () => {
    try {
      const d = await apiFetch('/api/agents/status')
      setAgents(Array.isArray(d.agents) ? d.agents : [])
      setErr(null)
    } catch (e) {
      if (e?.status === 404) {
        setAgents([])
        setErr(null)
        return
      }
      if (e?.status != null) {
        const b = e?.response ? await e.response.json().catch(() => ({})) : {}
        setErr(b.detail || t('agents.load_failed', { status: e.status }))
      } else {
        setErr(e.message || String(e))
      }
      setAgents([])
    } finally {
      setLoading(false)
    }
  }, [t])

  useEffect(() => {
    refresh()
  }, [refresh])

  // Auto-refresh every 15s, skipping ticks while the tab is hidden.
  useVisiblePolling(refresh, 15000, { paused: !autoRefresh })

  const createToken = useCallback(async () => {
    setActionErr(null)
    setGeneratedToken(null)
    const cid = Number(tokenClient)
    if (!cid) {
      setActionErr(t('agents.select_client_first'))
      return
    }
    try {
      const d = await apiFetch('/api/agents/enrollment-tokens', {
        method: 'POST',
        body: { client_id: cid, valid_minutes: Number(tokenValidity) || 60 },
      })
      setGeneratedToken(d)
    } catch (e) {
      setActionErr(e.message)
    }
  }, [tokenClient, tokenValidity, t])

  const fleetDispatch = useCallback(async () => {
    const cid = Number(tokenClient)
    if (!cid) {
      setActionErr(t('agents.select_client_first'))
      return
    }
    setFleetBusy(true)
    setActionErr(null)
    try {
      await apiFetch('/api/agents/dispatch', {
        method: 'POST',
        body: { client_id: cid, engine: 'process_inventory', fleet_broadcast: true },
      })
      await refresh()
    } catch (e) {
      setActionErr(e.message)
    } finally {
      setFleetBusy(false)
    }
  }, [tokenClient, refresh, t])

  const installLinux = useMemo(() => {
    if (!generatedToken) return ''
    const base = apiUrl('/install/agent.sh')
    return `curl -sSL ${base} | WEISSMAN_TOKEN="${generatedToken.enrollment_token}" WEISSMAN_SERVER="${apiUrl('')}" bash`
  }, [generatedToken])

  const installWindows = useMemo(() => {
    if (!generatedToken) return ''
    const base = apiUrl('/install/agent.ps1')
    return `iwr ${base} | iex; Install-WeissmanAgent -Token "${generatedToken.enrollment_token}" -Server "${apiUrl('')}"`
  }, [generatedToken])

  const metrics = useMemo(() => {
    const online = agents.filter((a) => a.online).length
    const clientsSeen = new Set(agents.map((a) => a.client_id)).size
    const capsTotal = agents.reduce((s, a) => s + (a.capabilities?.length || 0), 0)
    return { total: agents.length, online, offline: agents.length - online, clientsSeen, capsTotal }
  }, [agents])

  const filteredAgents = useMemo(() => {
    if (statusFilter === 'online') return agents.filter((a) => a.online)
    if (statusFilter === 'offline') return agents.filter((a) => !a.online)
    return agents
  }, [agents, statusFilter])

  const clientName = (id) => clients.find((c) => String(c.id) === String(id))?.name || `#${id}`

  const columns = useMemo(
    () => [
      columnHelper.accessor((a) => (a.online ? 'online' : a.last_seen_at ? 'offline' : 'never'), {
        id: 'status',
        header: t('agents.col_status'),
        cell: (ctx) => (
          <StatusBadge online={ctx.row.original.online} last_seen_at={ctx.row.original.last_seen_at} t={t} />
        ),
      }),
      columnHelper.accessor((a) => clientName(a.client_id), {
        id: 'client',
        header: t('agents.col_client'),
        cell: (ctx) => <span className="text-[var(--text-secondary)]">{ctx.getValue()}</span>,
      }),
      columnHelper.accessor((a) => a.hostname || '', {
        id: 'hostname',
        header: t('agents.col_hostname'),
        cell: (ctx) => <span className="text-[var(--text-primary)]">{ctx.getValue() || '—'}</span>,
      }),
      columnHelper.accessor((a) => `${a.os || ''} / ${a.arch || ''}`, {
        id: 'os',
        header: t('agents.col_os'),
        cell: (ctx) => <span className="text-[var(--text-tertiary)]">{ctx.getValue()}</span>,
      }),
      columnHelper.accessor((a) => a.agent_version || '', {
        id: 'version',
        header: t('agents.version'),
        cell: (ctx) => <span className="text-[var(--text-tertiary)]">{ctx.getValue() || '—'}</span>,
      }),
      columnHelper.accessor((a) => a.last_seen_at || '', {
        id: 'last_seen',
        header: t('agents.last_seen'),
        cell: (ctx) => <span className="text-[var(--text-muted)]">{timeAgo(ctx.getValue(), t)}</span>,
      }),
    ],
    // eslint-disable-next-line react-hooks/exhaustive-deps
    [t, clients], // clientName is derived from `clients`; rebuild when it changes
  )

  const listFindings = useMemo(() => agents.map((a) => ({
    id: a.agent_id || a.id,
    severity: a.online ? 'info' : 'medium',
    title: a.hostname || a.agent_id || 'Agent',
    type: 'agent',
    description: `Client ${clientName(a.client_id)} · ${a.capabilities?.length || 0} caps`,
    resource: String(a.client_id),
    // eslint-disable-next-line react-hooks/exhaustive-deps
  })), [agents, clients])

  const {
    exportCsv,
    filteredFindings,
    searchQuery,
    setSearchQuery,
  } = useFindingsWorkbench(listFindings, {
    csvPrefix: 'weissman-agents',
    haystackFn: (f) => `${f.title} ${f.type} ${f.description} ${f.resource}`,
  })

  const visibleAgents = useMemo(() => {
    if (!searchQuery.trim()) return filteredAgents
    const ids = new Set(filteredFindings.map((f) => f.id))
    return filteredAgents.filter((a) => ids.has(a.agent_id || a.id))
  }, [filteredAgents, filteredFindings, searchQuery])

  return (
    <PageShell
      title={t('agents.title')}
      subtitle={t('agents.subtitle')}
      badge={t('agents.badge')}
      badgeColor="#34d399"
      icon={<Server />}
      actions={(
        <div className="flex items-center gap-2 flex-wrap">
          <Button variant="unstyled"
            type="button"
            onClick={() => setAutoRefresh((v) => !v)}
            className={`px-3 py-1.5 rounded-lg border text-xs font-mono ${
              autoRefresh ? 'border-emerald-500/40 text-emerald-300 bg-emerald-500/10' : 'border-[var(--border-default)] text-[var(--text-tertiary)]'
            }`}
          >
            <Radio className={`w-3 h-3 inline mr-1 ${autoRefresh ? 'animate-pulse' : ''}`} />
            {autoRefresh ? t('agents.live_on') : t('agents.live_off')}
          </Button>
          <Link to="/nexus-swarm" className="text-[11px] font-mono px-2 py-1 rounded border border-violet-500/40 text-violet-300 hover:bg-violet-500/10">
            {t('nav.nexus_swarm', 'Nexus Swarm')}
          </Link>
          <ShellScanActions
            onRefresh={refresh}
            onExport={exportCsv}
            refreshLoading={loading}
            exportDisabled={!filteredFindings.length}
          />
        </div>
      )}
    >
      <div className="space-y-6">
        {loading && agents.length === 0 ? (
          <SkeletonWidgetGrid count={4} />
        ) : (
          <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
            <Kpi label={t('agents.kpi_registered')} value={metrics.total} color="#22d3ee" />
            <Kpi label={t('agents.kpi_online')} value={metrics.online} color="#34d399" />
            <Kpi label={t('agents.kpi_offline')} value={metrics.offline} color="#f87171" />
            <Kpi label={t('agents.kpi_capabilities')} value={metrics.capsTotal} color="#a78bfa" sub={t('agents.kpi_clients', { count: metrics.clientsSeen })} />
          </div>
        )}

        <section className="rounded-2xl bg-[var(--bg-2)] border border-[var(--border-default)] backdrop-blur-md p-5 space-y-4">
          <h2 className="text-xs font-mono uppercase tracking-widest text-[var(--text-tertiary)]">{t('agents.issue_token')}</h2>
          {(actionErr || err) && <div className="text-[12px] font-mono text-rose-400">{actionErr || err}</div>}
          <div className="grid grid-cols-1 sm:grid-cols-[1fr_180px_140px_auto] gap-3">
            <select
              value={tokenClient}
              onChange={(e) => setTokenClient(e.target.value)}
              className="bg-[var(--bg-3)] border border-[var(--border-default)] rounded-lg px-3 py-2 text-sm font-mono text-white"
            >
              <option value="">{t('agents.select_client')}</option>
              {clients.map((c) => (
                <option key={c.id} value={c.id}>{c.name} (#{c.id})</option>
              ))}
            </select>
            <input
              type="number"
              min={5}
              max={1440}
              value={tokenValidity}
              onChange={(e) => setTokenValidity(e.target.value)}
              className="bg-[var(--bg-3)] border border-[var(--border-default)] rounded-lg px-3 py-2 text-sm font-mono text-white"
              placeholder={t('agents.validity_minutes')}
            />
            <Button variant="unstyled"
              type="button"
              onClick={createToken}
              className="px-4 py-2 rounded-lg bg-cyan-500/20 border border-cyan-500/40 text-cyan-200 font-mono text-sm hover:bg-cyan-500/30"
            >
              {t('agents.generate_token')}
            </Button>
            <Button variant="unstyled"
              type="button"
              disabled={fleetBusy || !tokenClient}
              onClick={fleetDispatch}
              className="flex items-center justify-center gap-2 px-4 py-2 rounded-lg border border-violet-500/40 text-violet-300 font-mono text-sm hover:bg-violet-500/10 disabled:opacity-40"
            >
              <Zap className="w-3.5 h-3.5" />
              {fleetBusy ? t('agents.fleet_dispatching') : t('agents.fleet_dispatch')}
            </Button>
          </div>

          {generatedToken && (
            <div className="space-y-3 border-t border-[var(--border-default)] pt-4">
              <TokenBlock
                label={t('agents.token_one_time')}
                value={generatedToken.enrollment_token}
                hint={t('agents.valid_for', { minutes: generatedToken.expires_in_minutes, id: generatedToken.client_id })}
              />
              <TokenBlock label={t('agents.linux_macos')} value={installLinux} />
              <TokenBlock label={t('agents.windows_ps')} value={installWindows} />
            </div>
          )}
        </section>

        <div className="flex items-center gap-2 flex-wrap">
          {['all', 'online', 'offline'].map((f) => (
            <Button variant="unstyled"
              key={f}
              type="button"
              onClick={() => setStatusFilter(f)}
              className={`px-3 py-1.5 rounded-lg text-xs font-mono border transition-all ${
                statusFilter === f
                  ? 'bg-emerald-500/20 text-emerald-300 border-emerald-500/30'
                  : 'border-[var(--border-default)] text-[var(--text-muted)] hover:text-[var(--text-secondary)]'
              }`}
            >
              {t(`agents.filter_${f}`)}
            </Button>
          ))}
          <span className="text-[10px] font-mono text-[var(--text-muted)] ml-auto">
            {t('agents.registered_count', { total: visibleAgents.length })}
          </span>
        </div>

        <WeissmanListToolbar
          searchQuery={searchQuery}
          onSearchChange={setSearchQuery}
          resultCount={visibleAgents.length}
          totalCount={filteredAgents.length}
        />

        <div className="grid grid-cols-1 lg:grid-cols-[1fr_320px] gap-6">
          <section className="rounded-2xl bg-[var(--bg-2)] border border-[var(--border-default)] backdrop-blur-md p-5 overflow-hidden">
            <h2 className="text-xs font-mono uppercase tracking-widest text-[var(--text-tertiary)] mb-3">{t('agents.registered_heading')}</h2>
            {loading && agents.length === 0 ? (
              <SkeletonTable rows={4} cols={6} />
            ) : agents.length === 0 ? (
              <EmptyState
                icon="shield"
                title={t('agents.no_agents_title')}
                body={t('agents.no_agents')}
                cta={{ label: t('agents.generate_token'), onClick: () => document.querySelector('select')?.focus() }}
              />
            ) : filteredAgents.length === 0 ? (
              <EmptyState icon="search-x" title={t('agents.no_filter_title')} body={t('agents.no_filter_body')} />
            ) : visibleAgents.length === 0 ? (
              <div className="text-center py-8 text-[var(--text-muted)]">{t('weissmanFindings.filtered_title')}</div>
            ) : (
              <DataTable
                id="agents-table"
                columns={columns}
                data={visibleAgents}
                onRowClick={(row) => setSelectedAgent(row.original)}
                getRowId={(a) => a.agent_id}
                selectedRowId={selectedAgent?.agent_id ?? null}
                getRowAccentColor={(a) => (a.online ? '#34d399' : a.last_seen_at ? '#f87171' : undefined)}
                animateRows={false}
              />
            )}
          </section>

          <aside className="rounded-2xl bg-[var(--bg-2)] border border-[var(--border-default)] p-5 min-h-[200px]">
            <h3 className="text-xs font-mono uppercase tracking-widest text-[var(--text-muted)] mb-4">{t('agents.detail_heading')}</h3>
            {!selectedAgent ? (
              <p className="text-xs text-[var(--text-muted)]">{t('agents.detail_hint')}</p>
            ) : (
              <div className="space-y-4 text-sm">
                <div>
                  <div className="text-lg font-bold text-white">{selectedAgent.hostname}</div>
                  <StatusBadge online={selectedAgent.online} last_seen_at={selectedAgent.last_seen_at} t={t} />
                </div>
                <DetailRow label={t('agents.col_client')} value={clientName(selectedAgent.client_id)} />
                <DetailRow label={t('agents.agent_id')} value={selectedAgent.agent_id} mono copy />
                <DetailRow label={t('agents.col_os')} value={`${selectedAgent.os} / ${selectedAgent.arch}`} />
                <DetailRow label={t('agents.version')} value={selectedAgent.agent_version || '—'} />
                <DetailRow label={t('agents.last_seen')} value={timeAgo(selectedAgent.last_seen_at, t)} />
                <div>
                  <div className="text-[10px] font-mono uppercase text-[var(--text-muted)] mb-2">{t('agents.capabilities_heading')}</div>
                  {(selectedAgent.capabilities || []).length === 0 ? (
                    <span className="text-xs text-[var(--text-muted)]">{t('agents.no_capabilities')}</span>
                  ) : (
                    <div className="flex flex-wrap gap-1">
                      {selectedAgent.capabilities.map((cap) => (
                        <span key={cap} className="text-[10px] font-mono px-2 py-0.5 rounded bg-cyan-500/10 border border-cyan-500/25 text-cyan-300/80">
                          {cap}
                        </span>
                      ))}
                    </div>
                  )}
                </div>
                <Link to="/baseline-drift" className="text-xs text-violet-300/80 hover:text-violet-200 underline">
                  {t('agents.open_baseline')}
                </Link>
              </div>
            )}
          </aside>
        </div>
      </div>
    </PageShell>
  )
}

function Kpi({ label, value, color, sub }) {
  return (
    <div className="rounded-xl border border-[var(--border-default)] bg-[var(--bg-2)] p-4">
      <div className="text-[10px] font-mono uppercase text-[var(--text-muted)]">{label}</div>
      <div className="text-2xl font-bold mt-1" style={{ color }}>{value}</div>
      {sub && <div className="text-[10px] font-mono text-[var(--text-disabled)] mt-1">{sub}</div>}
    </div>
  )
}

function TokenBlock({ label, value, hint }) {
  return (
    <div>
      <div className="flex items-center justify-between mb-1">
        <div className="text-[10px] uppercase font-mono text-[var(--text-muted)]">{label}</div>
        <CopyButton value={value} label="Copy" />
      </div>
      <code className="block bg-[var(--bg-3)] border border-[var(--border-default)] rounded-lg p-3 text-xs font-mono text-emerald-300 break-all whitespace-pre-wrap">{value}</code>
      {hint && <div className="text-[10px] text-[var(--text-muted)] mt-1">{hint}</div>}
    </div>
  )
}

function DetailRow({ label, value, mono, copy }) {
  return (
    <div className="flex items-start justify-between gap-2">
      <span className="text-[10px] font-mono uppercase text-[var(--text-muted)] shrink-0">{label}</span>
      <div className="flex items-center gap-1 min-w-0">
        <span className={`text-xs text-[var(--text-secondary)] truncate ${mono ? 'font-mono' : ''}`}>{value}</span>
        {copy && <CopyButton value={value} />}
      </div>
    </div>
  )
}
