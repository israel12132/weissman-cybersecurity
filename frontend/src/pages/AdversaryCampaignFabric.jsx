/**
 * Adversary Campaign Fabric — evidence-grounded STRIPS campaigns.
 *
 * Operator starts a client-scoped campaign toward a planner goal. WorldState is
 * seeded from live findings (FP-suppressed rows excluded). Each step dispatches a
 * real engine job inside authorized scope. Route: /campaigns
 *
 * Live APIs: GET/POST /api/campaigns, POST …/start|pause, GET …/plan, GET …/steps.
 */
import { useState, useEffect, useCallback, useMemo } from 'react'
import { Link } from 'react-router'
import { useTranslation } from 'react-i18next'
import { Crosshair, Play, Pause, GitBranch } from 'lucide-react'
import PageShell from './PageShell'
import EmptyState from '../components/ui/EmptyState'
import ShellScanActions from '../components/engine/ShellScanActions'
import { SkeletonWidgetGrid } from '../components/ui/Skeleton'
import { useFindingsWorkbench } from '../hooks/useFindingsWorkbench'
import { useClient } from '../context/ClientContext'
import { apiFetch } from '../utils/apiFetch'
import { downloadCsv } from '../lib/exportFindingsCsv'
import Button from '../components/ui/Button'

const NS = 'pages.adversaryCampaign'

const STATUS_TONE = {
  draft: 'text-slate-300 border-slate-500/30 bg-slate-500/10',
  running: 'text-cyan-300 border-cyan-500/40 bg-cyan-500/10',
  paused: 'text-amber-300 border-amber-500/40 bg-amber-500/10',
  completed: 'text-emerald-300 border-emerald-500/40 bg-emerald-500/10',
  blocked: 'text-rose-300 border-rose-500/40 bg-rose-500/10',
  failed: 'text-rose-400 border-rose-500/50 bg-rose-900/20',
}

const STEP_TONE = {
  planned: 'text-[var(--text-muted)] border-[var(--border-default)]',
  dispatched: 'text-cyan-300 border-cyan-500/40 bg-cyan-500/10',
  succeeded: 'text-emerald-300 border-emerald-500/40 bg-emerald-500/10',
  failed: 'text-rose-300 border-rose-500/40 bg-rose-500/10',
  skipped: 'text-[var(--text-disabled)] border-[var(--border-default)]',
}

function StatusBadge({ status, ns = 'status' }) {
  const { t } = useTranslation()
  const tone = STATUS_TONE[status] || STEP_TONE[status] || 'text-[var(--text-muted)] border-[var(--border-default)]'
  return (
    <span className={`text-[10px] font-mono uppercase tracking-wider px-2 py-0.5 rounded border ${tone}`}>
      {t(`${NS}.${ns}_${status}`)}
    </span>
  )
}

function exportCampaignsCsv(rows) {
  const header = ['id', 'client_id', 'goal_fact', 'status', 'asset_key', 'updated_at']
  const data = rows.map((c) => [c.id, c.client_id, c.goal_fact, c.status, c.asset_key, c.updated_at])
  downloadCsv(data, header, 'weissman-campaigns')
}

export default function AdversaryCampaignFabric() {
  const { t } = useTranslation()
  const { clients, selectedClientId, setSelectedClientId } = useClient()

  const [campaigns, setCampaigns] = useState([])
  const [allowedGoals, setAllowedGoals] = useState(['impact:objective'])
  const [active, setActive] = useState(null)
  const [loading, setLoading] = useState(true)
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState('')
  const [goal, setGoal] = useState('impact:objective')

  const loadList = useCallback(async () => {
    setLoading(true)
    setError('')
    try {
      const qs = selectedClientId != null ? `?client_id=${encodeURIComponent(selectedClientId)}` : ''
      const data = await apiFetch(`/api/campaigns${qs}`)
      const list = Array.isArray(data?.campaigns) ? data.campaigns : []
      setCampaigns(list)
      if (Array.isArray(data?.allowed_goals) && data.allowed_goals.length) {
        setAllowedGoals(data.allowed_goals)
      }
    } catch (e) {
      setError(e.message || t(`${NS}.load_failed`))
      setCampaigns([])
    } finally {
      setLoading(false)
    }
  }, [selectedClientId, t])

  const loadOne = useCallback(async (id) => {
    if (!id) {
      setActive(null)
      return
    }
    try {
      const data = await apiFetch(`/api/campaigns/${encodeURIComponent(id)}`)
      const campaignClient = data?.campaign?.client_id
      if (
        selectedClientId != null &&
        campaignClient != null &&
        Number(campaignClient) !== Number(selectedClientId)
      ) {
        return
      }
      setActive(data)
    } catch (e) {
      setError(e.message || t(`${NS}.load_failed`))
    }
  }, [selectedClientId, t])

  useEffect(() => {
    setActive(null)
  }, [selectedClientId])

  useEffect(() => {
    loadList()
  }, [loadList])

  useEffect(() => {
    if (loading || active?.campaign?.id) return
    if (campaigns.length) loadOne(campaigns[0].id)
  }, [loading, campaigns, active?.campaign?.id, loadOne])

  useEffect(() => {
    const id = active?.campaign?.id
    if (!id || active?.campaign?.status !== 'running') return undefined
    const timer = setInterval(() => {
      loadOne(id)
      loadList()
    }, 4000)
    return () => clearInterval(timer)
  }, [active?.campaign?.id, active?.campaign?.status, loadList, loadOne])

  const createCampaign = useCallback(async () => {
    if (selectedClientId == null) return
    setBusy(true)
    setError('')
    try {
      const data = await apiFetch('/api/campaigns', {
        method: 'POST',
        body: JSON.stringify({ client_id: selectedClientId, goal }),
      })
      await loadList()
      if (data?.campaign?.id) await loadOne(data.campaign.id)
    } catch (e) {
      setError(e.message || t(`${NS}.create_failed`))
    } finally {
      setBusy(false)
    }
  }, [selectedClientId, goal, loadList, loadOne, t])

  const startCampaign = useCallback(async (id) => {
    setBusy(true)
    setError('')
    try {
      const data = await apiFetch(`/api/campaigns/${encodeURIComponent(id)}/start`, { method: 'POST' })
      setActive(data)
      await loadList()
    } catch (e) {
      setError(e.message || t(`${NS}.start_failed`))
    } finally {
      setBusy(false)
    }
  }, [loadList, t])

  const pauseCampaign = useCallback(async (id) => {
    setBusy(true)
    setError('')
    try {
      const data = await apiFetch(`/api/campaigns/${encodeURIComponent(id)}/pause`, { method: 'POST' })
      setActive(data)
      await loadList()
    } catch (e) {
      setError(e.message || t(`${NS}.pause_failed`))
    } finally {
      setBusy(false)
    }
  }, [loadList, t])

  const campaignRows = useMemo(
    () =>
      campaigns.map((c) => ({
        id: c.id,
        severity: c.status === 'blocked' || c.status === 'failed' ? 'high' : 'info',
        title: c.goal_fact,
        type: c.status,
        description: c.asset_key || '',
        resource: String(c.client_id ?? ''),
      })),
    [campaigns],
  )

  const { searchQuery, setSearchQuery, filteredFindings, exportCsv } = useFindingsWorkbench(
    campaignRows,
    {
      csvPrefix: 'weissman-campaigns',
      haystackFn: (f) => `${f.title} ${f.type} ${f.description} ${f.resource} ${f.id}`,
    },
  )

  const visible = useMemo(() => {
    const ids = new Set(filteredFindings.map((f) => String(f.id)))
    if (!searchQuery.trim()) return campaigns
    return campaigns.filter((c) => ids.has(String(c.id)))
  }, [campaigns, filteredFindings, searchQuery])

  const facts = active?.world_state?.facts
  const evidence = active?.world_state?.evidence || {}
  const steps = Array.isArray(active?.steps) ? active.steps : []
  const events = Array.isArray(active?.events) ? active.events : []
  const campaign = active?.campaign
  const mesh = active?.mesh

  return (
    <PageShell
      title={t(`${NS}.title`)}
      subtitle={t(`${NS}.subtitle`)}
      badge={t(`${NS}.badge`)}
      badgeColor="#ef4444"
      icon={<Crosshair className="w-5 h-5" />}
      actions={
        <div className="flex items-center gap-2 flex-wrap">
          <select
            value={selectedClientId ?? ''}
            onChange={(e) => setSelectedClientId(e.target.value ? Number(e.target.value) : null)}
            className="bg-[var(--bg-3)] border border-[var(--border-default)] rounded-lg px-2.5 py-1.5 text-xs text-[var(--text-secondary)] focus:outline-none"
            aria-label={t(`${NS}.select_client`)}
          >
            <option value="">{t(`${NS}.select_client`)}</option>
            {clients.map((c) => (
              <option key={c.id} value={c.id}>
                {c.name || c.domain || `#${c.id}`}
              </option>
            ))}
          </select>
          <select
            value={goal}
            onChange={(e) => setGoal(e.target.value)}
            className="bg-[var(--bg-3)] border border-[var(--border-default)] rounded-lg px-2.5 py-1.5 text-xs text-[var(--text-secondary)] focus:outline-none"
            aria-label={t(`${NS}.select_goal`)}
          >
            {allowedGoals.map((g) => (
              <option key={g} value={g}>
                {t(`${NS}.goal_${g.replace(':', '_')}`)}
              </option>
            ))}
          </select>
          <Button
            variant="unstyled"
            type="button"
            onClick={createCampaign}
            disabled={selectedClientId == null || busy}
            className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-lg border border-rose-500/40 bg-rose-500/10 text-rose-200 text-xs font-medium hover:bg-rose-500/20 disabled:opacity-40"
          >
            {t(`${NS}.create`)}
          </Button>
          <ShellScanActions
            onRefresh={() => {
              loadList()
              if (campaign?.id) loadOne(campaign.id)
            }}
            onExport={() => {
              exportCsv()
              exportCampaignsCsv(visible)
            }}
            refreshLoading={loading}
            exportDisabled={!visible.length}
          />
        </div>
      }
    >
      <div className="space-y-6">
        <p className="text-[11px] font-mono text-[var(--text-muted)]">{t(`${NS}.privacy_note`)}</p>

        <label className="block">
          <span className="sr-only">{t('common.search')}</span>
          <input
            type="search"
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
            placeholder={t(`${NS}.search_placeholder`)}
            className="w-full max-w-md bg-[var(--bg-3)] border border-[var(--border-default)] rounded-lg px-3 py-1.5 text-xs text-[var(--text-secondary)]"
          />
        </label>

        {error && (
          <div role="alert" className="rounded-xl border border-rose-500/30 bg-rose-950/20 px-4 py-3 text-sm text-rose-300 font-mono">
            {error}
          </div>
        )}

        {selectedClientId == null && (
          <EmptyState icon="building" title={t(`${NS}.pick_client_title`)} body={t(`${NS}.pick_client_body`)} />
        )}

        {selectedClientId != null && loading && <SkeletonWidgetGrid count={4} />}

        {selectedClientId != null && !loading && visible.length === 0 && (
          <EmptyState
            icon="network"
            title={t(`${NS}.empty_title`)}
            body={t(`${NS}.empty_body`)}
            action={
              <Button
                variant="unstyled"
                type="button"
                onClick={createCampaign}
                disabled={busy}
                className="inline-flex items-center gap-2 px-4 py-2 rounded-lg bg-rose-600 text-white text-sm font-medium hover:bg-rose-700 disabled:opacity-50"
              >
                {t(`${NS}.create`)}
              </Button>
            }
          />
        )}

        {selectedClientId != null && !loading && visible.length > 0 && (
          <div className="grid lg:grid-cols-[minmax(0,1fr)_minmax(0,1.4fr)] gap-4">
            <div className="space-y-2">
              <h2 className="text-[11px] font-mono uppercase tracking-widest text-[var(--text-muted)]">
                {t(`${NS}.list_heading`)}
              </h2>
              {visible.map((c) => (
                <button
                  key={c.id}
                  type="button"
                  onClick={() => loadOne(c.id)}
                  className={`w-full text-start rounded-xl border p-3 transition-colors ${
                    campaign?.id === c.id
                      ? 'border-rose-500/50 bg-rose-500/10'
                      : 'border-[var(--border-default)] bg-[var(--table-surface)] hover:border-[var(--border-strong)]'
                  }`}
                >
                  <div className="flex items-center justify-between gap-2 flex-wrap">
                    <span className="text-[11px] font-mono text-[var(--text-disabled)]">{String(c.id).slice(0, 8)}</span>
                    <StatusBadge status={c.status} />
                  </div>
                  <div className="mt-1 text-sm text-[var(--text-primary)] font-medium">{c.goal_fact}</div>
                  <div className="text-[11px] font-mono text-[var(--text-muted)]">
                    {c.asset_key || t(`${NS}.no_asset`)}
                  </div>
                </button>
              ))}
            </div>

            <div className="space-y-4">
              {!campaign && (
                <EmptyState icon="chart" title={t(`${NS}.select_campaign_title`)} body={t(`${NS}.select_campaign_body`)} />
              )}
              {campaign && (
                <>
                  <div className="flex items-center gap-2 flex-wrap">
                    <StatusBadge status={campaign.status} />
                    {(campaign.status === 'draft' || campaign.status === 'paused' || campaign.status === 'blocked' || campaign.status === 'failed') && (
                      <Button
                        variant="unstyled"
                        type="button"
                        onClick={() => startCampaign(campaign.id)}
                        disabled={busy}
                        className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-lg border border-cyan-500/40 text-cyan-200 text-xs hover:bg-cyan-500/10 disabled:opacity-40"
                      >
                        <Play className="w-3.5 h-3.5" />
                        {t(`${NS}.start`)}
                      </Button>
                    )}
                    {campaign.status === 'running' && (
                      <Button
                        variant="unstyled"
                        type="button"
                        onClick={() => pauseCampaign(campaign.id)}
                        disabled={busy}
                        className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-lg border border-amber-500/40 text-amber-200 text-xs hover:bg-amber-500/10 disabled:opacity-40"
                      >
                        <Pause className="w-3.5 h-3.5" />
                        {t(`${NS}.pause`)}
                      </Button>
                    )}
                    <Link
                      to="/kill-chain"
                      className="inline-flex items-center gap-1.5 text-[11px] font-mono text-cyan-300 hover:underline"
                    >
                      <GitBranch className="w-3.5 h-3.5" />
                      {t(`${NS}.open_kill_chain`)}
                    </Link>
                    <Link to="/attack-paths" className="text-[11px] font-mono text-cyan-300 hover:underline">
                      {t(`${NS}.open_attack_paths`)}
                    </Link>
                    <Link to="/jobs" className="text-[11px] font-mono text-cyan-300 hover:underline">
                      {t(`${NS}.open_jobs`)}
                    </Link>
                    <Link to="/council-queue" className="text-[11px] font-mono text-cyan-300 hover:underline">
                      {t(`${NS}.open_council`)}
                    </Link>
                    <Link to="/cem-dago" className="text-[11px] font-mono text-cyan-300 hover:underline">
                      {t(`${NS}.open_mesh`)}
                    </Link>
                  </div>
                  {campaign.last_error && (
                    <p className="text-[11px] font-mono text-rose-300">{campaign.last_error}</p>
                  )}

                  <div>
                    <h2 className="text-[11px] font-mono uppercase tracking-widest text-[var(--text-muted)] mb-2">
                      {t(`${NS}.mesh_heading`)}
                    </h2>
                    <p className="text-[12px] font-mono text-[var(--text-secondary)]">
                      {mesh?.enabled
                        ? t(`${NS}.mesh_enabled`, { id: mesh?.scan_id || '' })
                        : t(`${NS}.mesh_disabled`)}
                    </p>
                    <p className="text-[11px] text-[var(--text-muted)]">
                      {mesh?.world_state_on_blackboard ? t(`${NS}.mesh_seeded`) : t(`${NS}.mesh_unseeded`)}
                    </p>
                  </div>

                  <div>
                    <h2 className="text-[11px] font-mono uppercase tracking-widest text-[var(--text-muted)] mb-2">
                      {t(`${NS}.world_state`)}
                    </h2>
                    {(!facts || facts.length === 0) ? (
                      <p className="text-[12px] text-[var(--text-muted)]">{t(`${NS}.no_facts`)}</p>
                    ) : (
                      <ul className="flex flex-wrap gap-2">
                        {facts.map((fact) => (
                          <li
                            key={fact}
                            className="rounded-lg border border-cyan-500/30 bg-cyan-500/10 px-2 py-1 text-[11px] font-mono text-cyan-100"
                            title={(evidence[fact] || []).join(', ')}
                          >
                            <span>{fact}</span>
                            {Array.isArray(evidence[fact]) && evidence[fact].length > 0 && (
                              <span className="ms-1 text-[10px] text-cyan-300/70">×{evidence[fact].length}</span>
                            )}
                          </li>
                        ))}
                      </ul>
                    )}
                  </div>

                  <div>
                    <h2 className="text-[11px] font-mono uppercase tracking-widest text-[var(--text-muted)] mb-2">
                      {t(`${NS}.planned_chain`)}
                    </h2>
                    {steps.length === 0 ? (
                      <p className="text-[12px] text-[var(--text-muted)]">{t(`${NS}.no_steps`)}</p>
                    ) : (
                      <ol className="space-y-2">
                        {steps.map((s) => (
                          <li
                            key={s.id || s.seq}
                            className="rounded-xl border border-[var(--border-default)] bg-[var(--table-surface)] p-3"
                          >
                            <div className="flex items-center justify-between gap-2 flex-wrap">
                              <span className="text-[11px] font-mono text-[var(--text-disabled)]">
                                {t(`${NS}.step_n`, { n: s.seq })} · {s.mitre}
                              </span>
                              <StatusBadge status={s.status} ns="step" />
                            </div>
                            <div className="mt-1 text-sm text-[var(--text-primary)]">{s.technique_name}</div>
                            <div className="text-[11px] font-mono text-[var(--text-muted)]">
                              {s.engine_id}
                              {s.job_id ? ` · ${String(s.job_id).slice(0, 8)}` : ''}
                            </div>
                            {s.last_error && (
                              <p className="mt-1 text-[11px] text-rose-300">{s.last_error}</p>
                            )}
                          </li>
                        ))}
                      </ol>
                    )}
                  </div>

                  <div>
                    <h2 className="text-[11px] font-mono uppercase tracking-widest text-[var(--text-muted)] mb-2">
                      {t(`${NS}.event_log`)}
                    </h2>
                    {events.length === 0 ? (
                      <p className="text-[12px] text-[var(--text-muted)]">{t(`${NS}.no_events`)}</p>
                    ) : (
                      <ol className="space-y-1.5 max-h-64 overflow-auto">
                        {events.map((ev, i) => (
                          <li
                            key={`${ev.event_hash || i}-${ev.created_at}`}
                            className="rounded-lg border border-[var(--border-default)] px-2 py-1.5 text-[11px] font-mono text-[var(--text-secondary)]"
                          >
                            <span className="text-cyan-300">{ev.kind}</span>
                            <span className="ms-2 text-[var(--text-disabled)]">v{ev.event_version || 1}</span>
                          </li>
                        ))}
                      </ol>
                    )}
                  </div>
                </>
              )}
            </div>
          </div>
        )}
      </div>
    </PageShell>
  )
}
