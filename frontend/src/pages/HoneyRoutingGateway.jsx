import { useCommandCenterScan } from '../hooks/useCommandCenterScan'
import { useVisiblePolling } from '../hooks/useVisiblePolling'
import { useSyncHubScanParams } from '../hooks/useLaunchEngineScan'
import { useClientTargetPrefill } from '../hooks/useHubLocalScanParams'
import { useCallback, useEffect, useMemo, useRef, useState } from 'react'
import { useTranslation } from 'react-i18next'
import PageShell from './PageShell'
import ShellScanActions from '../components/engine/ShellScanActions'
import WeissmanFindingsPanel from '../components/engine/WeissmanFindingsPanel'
import { useWeissmanEnginePage, applyHistoryFindings } from '../hooks/useWeissmanEnginePage'
import { apiFetch } from '../utils/apiFetch'
import { ENGINES_BY_ID } from '../lib/enginesRegistry'

const ENGINE_ID = 'honey_routing_gateway'

const DEFAULT_PARAMS = {
  probe_decoys: true,
  include_risk_graph: true,
  include_fair_aro: true,
}

function MetricCard({ label, value, sub, color = 'text-amber-300' }) {
  return (
    <div className="px-4 py-3 rounded-xl bg-[var(--bg-2)] border border-[var(--border-default)] text-center">
      <p className={`text-2xl font-mono font-bold ${color}`}>{value}</p>
      <p className="text-[10px] text-[var(--text-muted)] uppercase mt-1">{label}</p>
      {sub && <p className="text-[10px] text-[var(--text-disabled)] mt-0.5 font-mono">{sub}</p>}
    </div>
  )
}

export default function HoneyRoutingGateway() {
  const { t } = useTranslation()
  const [params, setParams] = useState(DEFAULT_PARAMS)
  useSyncHubScanParams(ENGINE_ID, params)
  const [clients, setClients] = useState([])
  const [clientId, setClientId] = useState('')
  const { postScan } = useCommandCenterScan(clientId)
  const [target, setTarget] = useState('')
  const [findings, setFindings] = useState([])
  const [dashboard, setDashboard] = useState(null)
  const [payloads, setPayloads] = useState([])
  const [selectedSession, setSelectedSession] = useState(null)
  const [sessionSearch, setSessionSearch] = useState('')
  const [runState, setRunState] = useState({ running: false, msg: '' })
  const [jobId, setJobId] = useState('')
  const [lastUpdated, setLastUpdated] = useState(null)
  const [autoRun, setAutoRun] = useState(false)
  const [isolateMsg, setIsolateMsg] = useState('')
  const autoRanRef = useRef(false)
  const engine = ENGINES_BY_ID[ENGINE_ID]

  const readiness = useMemo(() => ({
    hasClient: Boolean(clientId),
    hasTarget: Boolean(target.trim()),
    ready: Boolean(clientId) && Boolean(target.trim()),
  }), [clientId, target])

  const {
    searchQuery,
    setSearchQuery,
    filteredFindings,
    refreshFromHistory,
    historyLoading,
  } = useWeissmanEnginePage(ENGINE_ID, findings, {
    csvPrefix: 'weissman-honey-routing',
    haystackFn: (f) => `${f.title} ${f.type} ${f.description} ${f.severity}`,
  })

  const loadDashboard = useCallback(async () => {
    if (!clientId) return
    try {
      const dash = await apiFetch(`/api/honey-routing/${clientId}/dashboard`)
      if (dash) {
        setDashboard(dash)
        setLastUpdated(new Date().toISOString())
      }
    } catch {
      /* live fetch failed — keep last snapshot */
    }
  }, [clientId])

  useEffect(() => {
    apiFetch('/api/clients')
      .then((d) => { if (Array.isArray(d)) setClients(d) })
      .catch(() => {})
  }, [])

  useClientTargetPrefill(clientId, clients, setTarget, { onlyIfEmpty: false })

  useEffect(() => {
    loadDashboard()
  }, [loadDashboard])
  useVisiblePolling(loadDashboard, 8000)

  const runEngine = useCallback(async (isAuto = false) => {
    if (!clientId || !target.trim()) {
      setRunState({ running: false, msg: t('pages.honeyRouting.need_client_target') })
      return
    }
    setRunState({ running: true, msg: isAuto ? t('pages.honeyRouting.auto_run') : t('pages.honeyRouting.running') })
    if (!isAuto) setFindings([])
    try {
      const { ok, data: d, status } = await postScan({
        engine: ENGINE_ID,
        client_id: Number(clientId),
        target: target.trim(),
        timeout: 180,
        ...params,
      })
      if (!ok) {
        setRunState({ running: false, msg: d.detail || `HTTP ${status}` })
        return
      }
      setJobId(d.job_id || '')
      setRunState({ running: true, msg: t('pages.honeyRouting.queued', { jobId: d.job_id }) })
    } catch (e) {
      setRunState({ running: false, msg: e?.message || 'Network error' })
    }
  }, [clientId, target, params, t, postScan])

  useEffect(() => {
    if (!autoRun || autoRanRef.current || runState.running || !readiness.ready) return
    autoRanRef.current = true
    runEngine(true)
  }, [autoRun, readiness.ready, runState.running, runEngine])

  useEffect(() => {
    refreshFromHistory().then((run) => {
      applyHistoryFindings(run, setFindings, { setLastUpdated, setJobId })
    })
  }, [refreshFromHistory])

  useEffect(() => {
    if (!jobId || !runState.running) return undefined
    let cancelled = false
    const iv = setInterval(async () => {
      try {
        const d = await apiFetch(`/api/jobs/${encodeURIComponent(jobId)}`)
        if (cancelled || !d) return
        const status = String(d.status || '').toLowerCase()
        if (status === 'completed') {
          const raw = d.result_json || d.result || {}
          setFindings(Array.isArray(raw.findings) ? raw.findings : [])
          setLastUpdated(new Date().toISOString())
          setRunState({ running: false, msg: t('pages.honeyRouting.complete') })
          loadDashboard()
        } else if (status === 'failed' || status === 'dead') {
          setRunState({ running: false, msg: d.error || status })
        }
      } catch { /* retry */ }
    }, 2500)
    return () => { cancelled = true; clearInterval(iv) }
  }, [jobId, runState.running, loadDashboard, t])

  const openSession = async (session) => {
    setSelectedSession(session)
    setIsolateMsg('')
    try {
      const d = await apiFetch(`/api/honey-routing/${clientId}/sessions/${session.id}`)
      setPayloads(Array.isArray(d?.payloads) ? d.payloads : [])
    } catch {
      setPayloads([])
    }
  }

  const requestIsolate = async () => {
    if (!clientId || !selectedSession?.id) {
      setIsolateMsg(t('pages.honeyRouting.isolate_need_session'))
      return
    }
    try {
      const d = await apiFetch(
        `/api/honey-routing/${clientId}/sessions/${selectedSession.id}/isolate-request`,
        { method: 'POST' },
      )
      setIsolateMsg(d?.needs_second_admin ? t('pages.honeyRouting.isolate_pending') : JSON.stringify(d))
      loadDashboard()
    } catch (e) {
      setIsolateMsg(e?.message || 'isolate request failed')
    }
  }

  const approveIsolate = async () => {
    if (!clientId || !selectedSession?.id) {
      setIsolateMsg(t('pages.honeyRouting.isolate_need_session'))
      return
    }
    try {
      const d = await apiFetch(
        `/api/honey-routing/${clientId}/sessions/${selectedSession.id}/isolate-approve`,
        { method: 'POST', body: { confirm: 'ISOLATE' } },
      )
      setIsolateMsg(d?.ok ? t('pages.honeyRouting.isolate_done') : (d?.error || JSON.stringify(d)))
      loadDashboard()
    } catch (e) {
      setIsolateMsg(e?.message || 'isolate approve failed')
    }
  }

  const sessions = Array.isArray(dashboard?.sessions) ? dashboard.sessions : []
  const q = sessionSearch.trim().toLowerCase()
  const filteredSessions = q
    ? sessions.filter((s) => `${s.source_ip} ${s.decoy_path} ${s.user_agent}`.toLowerCase().includes(q))
    : sessions

  return (
    <PageShell
      hideHubParams
      engineId={ENGINE_ID}
      title={t('pages.honeyRouting.title')}
      subtitle={t('pages.honeyRouting.subtitle')}
      badge={t('pages.honeyRouting.badge')}
      badgeColor="#f59e0b"
      icon="🕸"
      maxWidth="max-w-[1680px]"
      syncAt={lastUpdated}
      evidence={t('pages.honeyRouting.evidence_notice')}
      breadcrumbs={[
        { label: t('nav.engines'), to: '/engine-matrix' },
        { label: t('pages.honeyRouting.breadcrumb') },
      ]}
      actions={(
        <ShellScanActions
          running={runState.running}
          onRun={() => runEngine(false)}
          onRefresh={() => { refreshFromHistory(); loadDashboard() }}
          refreshLoading={historyLoading}
          runLabel={t('pages.honeyRouting.run')}
        />
      )}
    >
      <div className="rounded-xl border border-amber-500/30 bg-amber-950/20 px-4 py-3 mb-6 text-[11px] text-amber-100/90 font-mono leading-relaxed">
        {t('pages.honeyRouting.security_notice')}
      </div>

      <div className="grid grid-cols-2 md:grid-cols-4 gap-3 mb-6">
        <MetricCard
          label={t('pages.honeyRouting.metric_sessions')}
          value={dashboard?.sessions_24h ?? '—'}
          sub={t('pages.honeyRouting.sessions_24h')}
          color="text-amber-300"
        />
        <MetricCard
          label={t('pages.honeyRouting.metric_payloads')}
          value={dashboard?.payloads_24h ?? '—'}
          sub={t('pages.honeyRouting.captured')}
          color="text-cyan-300"
        />
        <MetricCard
          label={t('pages.honeyRouting.metric_high')}
          value={dashboard?.high_confidence_24h ?? '—'}
          sub={t('pages.honeyRouting.high_conf')}
          color="text-rose-400"
        />
        <MetricCard
          label={t('pages.honeyRouting.metric_aro')}
          value={dashboard?.fair_aro_floor ?? '—'}
          sub={t('pages.honeyRouting.fair_aro')}
          color="text-emerald-300"
        />
      </div>

      <div className="grid grid-cols-1 xl:grid-cols-12 gap-6">
        <div className="xl:col-span-4 space-y-4">
          <div className="rounded-2xl border border-[var(--border-default)] bg-gradient-to-b from-amber-950/20 to-black/40 p-4 space-y-4">
            <h3 className="text-sm font-semibold text-white">{t('pages.honeyRouting.controls')}</h3>
            <label className="flex items-center gap-2 text-[11px] text-[var(--text-secondary)] cursor-pointer">
              <input type="checkbox" checked={autoRun} onChange={(e) => setAutoRun(e.target.checked)} />
              {t('pages.honeyRouting.auto_run_label')}
            </label>
            <div>
              <label className="text-[10px] font-mono uppercase text-[var(--text-muted)]">{t('pages.honeyRouting.client')}</label>
              <select
                className="w-full mt-1 bg-black/40 border border-[var(--border-default)] rounded-lg px-3 py-2 text-sm"
                value={clientId}
                onChange={(e) => setClientId(e.target.value)}
              >
                <option value="">{t('pages.honeyRouting.select_client')}</option>
                {clients.map((c) => (
                  <option key={c.id} value={c.id}>{c.name || c.slug || c.id}</option>
                ))}
              </select>
            </div>
            <div>
              <label className="text-[10px] font-mono uppercase text-[var(--text-muted)]">{t('pages.honeyRouting.target')}</label>
              <input
                className="w-full mt-1 bg-black/40 border border-[var(--border-default)] rounded-lg px-3 py-2 text-sm font-mono"
                value={target}
                onChange={(e) => setTarget(e.target.value)}
                placeholder="https://gateway.example"
              />
            </div>
            <label className="flex items-center gap-2 text-[11px] text-[var(--text-secondary)] cursor-pointer">
              <input type="checkbox" checked={params.probe_decoys} onChange={(e) => setParams((p) => ({ ...p, probe_decoys: e.target.checked }))} />
              {t('pages.honeyRouting.probe_decoys')}
            </label>
            <label className="flex items-center gap-2 text-[11px] text-[var(--text-secondary)] cursor-pointer">
              <input type="checkbox" checked={params.include_risk_graph} onChange={(e) => setParams((p) => ({ ...p, include_risk_graph: e.target.checked }))} />
              {t('pages.honeyRouting.include_graph')}
            </label>
            <label className="flex items-center gap-2 text-[11px] text-[var(--text-secondary)] cursor-pointer">
              <input type="checkbox" checked={params.include_fair_aro} onChange={(e) => setParams((p) => ({ ...p, include_fair_aro: e.target.checked }))} />
              {t('pages.honeyRouting.include_fair')}
            </label>
            {runState.msg && <p className="text-[11px] font-mono text-amber-200/80">{runState.msg}</p>}
            <p className="text-[10px] text-[var(--text-muted)] font-mono">
              {t('pages.honeyRouting.decoy_paths')}: {(dashboard?.decoys || []).join(' · ') || '/api/v1/auth/admin · /api/v1/debug/shell'}
            </p>
          </div>
        </div>

        <div className="xl:col-span-8 space-y-4">
          <div className="rounded-2xl border border-[var(--border-default)] bg-black/30 p-4">
            <div className="flex flex-wrap items-center justify-between gap-2 mb-3">
              <h3 className="text-sm font-semibold text-white">{t('pages.honeyRouting.live_sessions')}</h3>
              <input
                type="search"
                value={sessionSearch}
                onChange={(e) => setSessionSearch(e.target.value)}
                placeholder={t('pages.honeyRouting.search_sessions')}
                className="bg-black/40 border border-[var(--border-default)] rounded-lg px-3 py-1.5 text-xs font-mono w-56"
              />
            </div>
            {filteredSessions.length === 0 ? (
              <p className="text-[12px] text-[var(--text-muted)]">{t('pages.honeyRouting.no_sessions')}</p>
            ) : (
              <div className="overflow-x-auto">
                <table className="w-full text-[11px] font-mono">
                  <thead className="text-[var(--text-muted)] uppercase text-[10px]">
                    <tr>
                      <th className="text-left py-1">{t('pages.honeyRouting.col_ip')}</th>
                      <th className="text-left py-1">{t('pages.honeyRouting.col_path')}</th>
                      <th className="text-left py-1">{t('pages.honeyRouting.col_conf')}</th>
                      <th className="text-left py-1">{t('pages.honeyRouting.col_hits')}</th>
                      <th className="text-left py-1">{t('pages.honeyRouting.col_mitre')}</th>
                    </tr>
                  </thead>
                  <tbody>
                    {filteredSessions.map((s) => (
                      <tr
                        key={s.id}
                        className={`border-t border-white/5 cursor-pointer hover:bg-amber-950/20 ${selectedSession?.id === s.id ? 'bg-amber-950/30' : ''}`}
                        onClick={() => openSession(s)}
                      >
                        <td className="py-1.5 text-amber-200">{s.source_ip}</td>
                        <td className="py-1.5 truncate max-w-[220px]">{s.decoy_path}</td>
                        <td className={s.high_confidence ? 'text-rose-400' : 'text-cyan-300'}>
                          {s.confidence}{s.lateral_attempt ? ' ⚡' : ''}
                        </td>
                        <td>{s.hit_count}</td>
                        <td className="truncate max-w-[180px]">{(s.mitre_techniques || []).join(', ')}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
          </div>

          {selectedSession && (
            <div className="rounded-2xl border border-rose-500/20 bg-rose-950/10 p-4">
              <h3 className="text-sm font-semibold text-white mb-2">{t('pages.honeyRouting.payloads_for', { ip: selectedSession.source_ip })}</h3>
              {payloads.length === 0 ? (
                <p className="text-[12px] text-[var(--text-muted)]">{t('pages.honeyRouting.no_payloads')}</p>
              ) : (
                <ul className="space-y-2 max-h-56 overflow-y-auto">
                  {payloads.map((p) => (
                    <li key={p.id} className="text-[11px] font-mono border border-white/10 rounded-lg px-3 py-2">
                      <span className="text-cyan-300">{p.method}</span> {p.path}
                      {p.shell_command && <div className="text-amber-200 mt-1">$ {p.shell_command}</div>}
                      {p.body_excerpt && <div className="text-[var(--text-muted)] mt-1 truncate">{p.body_excerpt}</div>}
                    </li>
                  ))}
                </ul>
              )}
              <div className="mt-3 flex flex-wrap gap-2">
                <button
                  type="button"
                  onClick={requestIsolate}
                  className="px-3 py-1.5 rounded-lg text-[11px] font-mono border border-amber-500/40 text-amber-200 hover:bg-amber-950/40"
                >
                  {t('pages.honeyRouting.isolate_request')}
                </button>
                <button
                  type="button"
                  onClick={approveIsolate}
                  className="px-3 py-1.5 rounded-lg text-[11px] font-mono border border-rose-500/40 text-rose-200 hover:bg-rose-950/40"
                >
                  {t('pages.honeyRouting.isolate_approve')}
                </button>
              </div>
              {isolateMsg && <p className="mt-2 text-[11px] font-mono text-amber-200/80">{isolateMsg}</p>}
            </div>
          )}

          <WeissmanFindingsPanel
            findings={filteredFindings}
            searchQuery={searchQuery}
            onSearchChange={setSearchQuery}
            title={t('pages.honeyRouting.findings', { engine: engine?.label || ENGINE_ID })}
            emptyMessage={t('pages.honeyRouting.no_findings')}
          />
        </div>
      </div>
    </PageShell>
  )
}
