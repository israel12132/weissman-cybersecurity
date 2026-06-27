import { useCommandCenterScan } from '../hooks/useCommandCenterScan'
import { useSyncHubScanParams } from '../hooks/useLaunchEngineScan'
import { useClientTargetPrefill } from '../hooks/useHubLocalScanParams'
import React, { useCallback, useEffect, useMemo, useRef, useState } from 'react'
import { Link } from 'react-router-dom'
import { motion, AnimatePresence } from 'framer-motion'
import { useTranslation } from 'react-i18next'
import PageShell from './PageShell'
import ShellScanActions from '../components/engine/ShellScanActions'
import WeissmanFindingsPanel from '../components/engine/WeissmanFindingsPanel'
import { useWeissmanEnginePage, applyHistoryFindings } from '../hooks/useWeissmanEnginePage'
import { apiFetch } from '../lib/apiBase'
import { ENGINES_BY_ID } from '../lib/enginesRegistry'

const ENGINES = {
  chronos: 'chronos',
  liquid: 'liquid_matrix',
  cognitive: 'cognitive_starvation',
}

const TABS = ['chronos', 'liquid', 'cognitive']

const DEFAULT_PARAMS = {
  chronos: {
    sample_interval_ms: '5',
    observation_window_ms: '5000',
    auto_freeze: true,
    deploy_ebpf: false,
    ebpf_ssh_host: '',
    ebpf_ssh_user: '',
    ebpf_ssh_key_path: '',
    ebpf_ssh_key_pem: '',
    ebpf_ssh_port: '22',
  },
  liquid: {
    rotation_step_secs: '3',
    port_pool_min: '30000',
    port_pool_max: '39999',
    probe_gateway: true,
  },
  cognitive: {
    min_bot_score: '0.55',
    deploy_shadow: true,
    poison_variants: 'adversarial_prompt,zip_bomb_meta,xml_entity,shadow_api',
    probe_rate: '8',
  },
}

function TabButton({ active, label, onClick }) {
  return (
    <button
      type="button"
      onClick={onClick}
      className={`px-4 py-2 text-xs font-mono uppercase tracking-wider rounded-lg border transition-colors ${
        active
          ? 'border-cyan-400/60 bg-cyan-950/40 text-cyan-200'
          : 'border-white/10 text-white/50 hover:border-white/25 hover:text-white/80'
      }`}
    >
      {label}
    </button>
  )
}

function MetricCard({ label, value, sub, color = 'text-cyan-300' }) {
  return (
    <div className="px-4 py-3 rounded-xl bg-black/40 border border-white/10 text-center">
      <p className={`text-2xl font-mono font-bold ${color}`}>{value}</p>
      <p className="text-[10px] text-white/40 uppercase mt-1">{label}</p>
      {sub && <p className="text-[10px] text-white/30 mt-0.5 font-mono">{sub}</p>}
    </div>
  )
}

function buildScanBody(engineId, params, clientId, target) {
  return {
    engine: engineId,
    client_id: Number(clientId),
    target: (target || '').trim(),
    timeout: 180,
    ...params,
  }
}

export default function SovereignDefenseMatrix() {
  const { t } = useTranslation()
  const [tab, setTab] = useState('chronos')
  const [params, setParams] = useState(DEFAULT_PARAMS)
  const hubTabParams = useMemo(() => params[tab] || {}, [params, tab])
  useSyncHubScanParams(ENGINES[tab], hubTabParams)
  const [clients, setClients] = useState([])
  const [clientId, setClientId] = useState('')
  const { postScan } = useCommandCenterScan(clientId)
  const [target, setTarget] = useState('')
  const [findings, setFindings] = useState([])
  const [dashboard, setDashboard] = useState(null)
  const [chronosEvents, setChronosEvents] = useState([])
  const [cognitiveSessions, setCognitiveSessions] = useState([])
  const [poisonLib, setPoisonLib] = useState([])
  const [runState, setRunState] = useState({ running: false, msg: '' })
  const [jobId, setJobId] = useState('')
  const [lastUpdated, setLastUpdated] = useState(null)
  const [autoRun, setAutoRun] = useState(true)
  const autoRanRef = useRef(false)

  const engineId = ENGINES[tab]
  const engine = ENGINES_BY_ID[engineId]

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
  } = useWeissmanEnginePage(engineId, findings, {
    csvPrefix: 'weissman-sovereign-defense',
    haystackFn: (f) => `${f.title} ${f.type} ${f.description} ${f.severity}`,
  })

  const setP = useCallback((section, key, val) => {
    setParams((prev) => ({
      ...prev,
      [section]: { ...prev[section], [key]: val },
    }))
  }, [])

  const loadDashboard = useCallback(async () => {
    if (!clientId) return
    const r = await apiFetch(`/api/sovereign-defense/${clientId}/dashboard`)
    if (r.ok) setDashboard(await r.json())
    const ce = await apiFetch(`/api/sovereign-defense/${clientId}/chronos/events`)
    if (ce.ok) setChronosEvents(await ce.json())
    const cs = await apiFetch(`/api/sovereign-defense/${clientId}/cognitive/sessions`)
    if (cs.ok) setCognitiveSessions(await cs.json())
  }, [clientId])

  const loadPoisonLib = useCallback(async () => {
    const r = await apiFetch('/api/sovereign-defense/poison-library')
    if (r.ok) setPoisonLib(await r.json())
  }, [])

  useEffect(() => {
    apiFetch('/api/clients')
      .then((r) => (r.ok ? r.json() : []))
      .then((d) => { if (Array.isArray(d)) setClients(d) })
      .catch(() => {})
    loadPoisonLib()
  }, [loadPoisonLib])

  useClientTargetPrefill(clientId, clients, setTarget, { onlyIfEmpty: false })

  useEffect(() => {
    loadDashboard()
    const iv = setInterval(loadDashboard, 3000)
    return () => clearInterval(iv)
  }, [loadDashboard])

  const runEngine = useCallback(async (isAuto = false) => {
    if (!clientId || !target.trim()) {
      setRunState({ running: false, msg: t('pages.sovereignDefense.need_client_target') })
      return
    }
    setRunState({ running: true, msg: isAuto ? t('pages.sovereignDefense.auto_run') : t('pages.sovereignDefense.running') })
    if (!isAuto) setFindings([])
    const body = buildScanBody(engineId, params[tab], clientId, target)
    try {
      const { ok, data: d, status } = await postScan(body)
      if (!ok) {
        setRunState({ running: false, msg: d.detail || `HTTP ${status}` })
        return
      }
      setJobId(d.job_id || '')
      setRunState({ running: true, msg: t('pages.sovereignDefense.queued', { jobId: d.job_id }) })
    } catch (e) {
      setRunState({ running: false, msg: e?.message || 'Network error' })
    }
  }, [clientId, target, engineId, params, tab, t])

  useEffect(() => {
    if (!autoRun || autoRanRef.current || runState.running || !readiness.ready) return
    autoRanRef.current = true
    runEngine(true)
  }, [autoRun, readiness.ready, runState.running, runEngine])

  useEffect(() => {
    refreshFromHistory().then((run) => {
      applyHistoryFindings(run, setFindings, { setLastUpdated, setJobId })
    })
  }, [refreshFromHistory, engineId])

  useEffect(() => {
    if (!jobId || !runState.running) return undefined
    const iv = setInterval(async () => {
      const r = await apiFetch(`/api/jobs/${encodeURIComponent(jobId)}`)
      const d = await r.json().catch(() => null)
      if (!ok || !d) return
      const status = String(d.status || '').toLowerCase()
      if (status === 'completed') {
        const raw = d.result_json || d.result || {}
        setFindings(Array.isArray(raw.findings) ? raw.findings : [])
        setLastUpdated(new Date().toISOString())
        setRunState({ running: false, msg: t('pages.sovereignDefense.complete') })
        loadDashboard()
      } else if (status === 'failed' || status === 'dead') {
        setRunState({ running: false, msg: d.error || status })
      }
    }, 2500)
    return () => clearInterval(iv)
  }, [jobId, runState.running, loadDashboard, t])

  const rotateLiquid = async () => {
    if (!clientId) return
    const r = await apiFetch(`/api/sovereign-defense/${clientId}/liquid-matrix/rotate`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        rotation_step_secs: Number(params.liquid.rotation_step_secs),
        port_pool_min: Number(params.liquid.port_pool_min),
        port_pool_max: Number(params.liquid.port_pool_max),
      }),
    })
    if (r.ok) loadDashboard()
  }

  const liquid = dashboard?.liquid_matrix
  const chronos = dashboard?.chronos

  return (
    <PageShell
      hideHubParams
      engineId={engineId}
      title={t('pages.sovereignDefense.title')}
      subtitle={t('pages.sovereignDefense.subtitle')}
      badge={t('pages.sovereignDefense.badge')}
      badgeColor="#06b6d4"
      icon="⬡"
      maxWidth="max-w-[1680px]"
      syncAt={lastUpdated}
      evidence={t('pages.sovereignDefense.evidence_notice')}
      breadcrumbs={[
        { label: t('nav.engines'), to: '/engine-matrix' },
        { label: t('pages.sovereignDefense.breadcrumb') },
      ]}
      actions={(
        <ShellScanActions
          running={runState.running}
          onRun={() => runEngine(false)}
          onRefresh={refreshFromHistory}
          refreshLoading={historyLoading}
          runLabel={t('pages.sovereignDefense.run')}
        />
      )}
    >
      <div className="rounded-xl border border-cyan-500/25 bg-cyan-950/15 px-4 py-3 mb-6 text-[11px] text-cyan-100/90 font-mono leading-relaxed">
        {t('pages.sovereignDefense.security_notice')}
      </div>

      <div className="flex flex-wrap gap-2 mb-6">
        {TABS.map((id) => (
          <TabButton
            key={id}
            active={tab === id}
            label={t(`pages.sovereignDefense.tab_${id}`)}
            onClick={() => setTab(id)}
          />
        ))}
      </div>

      <div className="grid grid-cols-2 md:grid-cols-4 gap-3 mb-6">
        <MetricCard
          label={t('pages.sovereignDefense.metric_chronos')}
          value={chronos?.freezes_24h ?? '—'}
          sub={`${chronos?.events_24h ?? 0} events`}
          color="text-violet-300"
        />
        <MetricCard
          label={t('pages.sovereignDefense.metric_liquid')}
          value={liquid?.routing_code ?? '—'}
          sub={liquid ? `${liquid.internal_ip}:${liquid.internal_port}` : ''}
          color="text-cyan-300"
        />
        <MetricCard
          label={t('pages.sovereignDefense.metric_cognitive')}
          value={dashboard?.cognitive_starvation?.sessions_24h ?? '—'}
          sub={t('pages.sovereignDefense.sessions_24h')}
          color="text-amber-300"
        />
        <MetricCard
          label={t('pages.sovereignDefense.metric_agent')}
          value={chronos?.agent_online ? 'ONLINE' : 'OFF'}
          sub={t('pages.sovereignDefense.agent_status')}
          color={chronos?.agent_online ? 'text-emerald-400' : 'text-red-400'}
        />
      </div>

      <div className="grid grid-cols-1 xl:grid-cols-12 gap-6">
        <div className="xl:col-span-4 space-y-4">
          <div className="rounded-2xl border border-white/10 bg-gradient-to-b from-cyan-950/25 to-black/40 p-4 space-y-4">
            <h3 className="text-sm font-semibold text-white">{t('pages.sovereignDefense.controls')}</h3>

            <label className="flex items-center gap-2 text-[11px] text-white/75 cursor-pointer">
              <input type="checkbox" checked={autoRun} onChange={(e) => setAutoRun(e.target.checked)} />
              {t('pages.sovereignDefense.auto_run_label')}
            </label>

            <label className="block text-[11px] font-mono text-white/60">
              {t('pages.sovereignDefense.client')}
              <select
                value={clientId}
                onChange={(e) => setClientId(e.target.value)}
                className="mt-1 w-full rounded-lg bg-black/50 border border-white/15 px-3 py-2 text-sm text-white"
              >
                <option value="">{t('pages.sovereignDefense.select_client')}</option>
                {clients.map((c) => (
                  <option key={c.id} value={c.id}>{c.name || c.id}</option>
                ))}
              </select>
            </label>

            <label className="block text-[11px] font-mono text-white/60">
              {t('pages.sovereignDefense.target')}
              <input
                type="url"
                value={target}
                onChange={(e) => setTarget(e.target.value)}
                className="mt-1 w-full rounded-lg bg-black/50 border border-white/15 px-3 py-2 text-sm font-mono text-white"
              />
            </label>

            {runState.msg && (
              <p className="text-[11px] font-mono text-cyan-300/90">{runState.msg}</p>
            )}

            <AnimatePresence mode="wait">
              {tab === 'chronos' && (
                <motion.div key="chronos-params" initial={{ opacity: 0 }} animate={{ opacity: 1 }} className="space-y-3">
                  <label className="block text-[11px] text-white/60">
                    {t('pages.sovereignDefense.chronos_sample_interval')}
                    <input type="number" value={params.chronos.sample_interval_ms}
                      onChange={(e) => setP('chronos', 'sample_interval_ms', e.target.value)}
                      className="mt-1 w-full rounded-lg bg-black/40 border border-white/10 px-2 py-1.5 text-xs text-white" />
                  </label>
                  <label className="block text-[11px] text-white/60">
                    {t('pages.sovereignDefense.chronos_observation_window')}
                    <input type="number" value={params.chronos.observation_window_ms}
                      onChange={(e) => setP('chronos', 'observation_window_ms', e.target.value)}
                      className="mt-1 w-full rounded-lg bg-black/40 border border-white/10 px-2 py-1.5 text-xs text-white" />
                  </label>
                  <div className="rounded-xl border border-violet-500/20 bg-violet-950/15 p-3 space-y-2">
                    <div className="text-[10px] font-mono uppercase text-violet-300/80">
                      {t('pages.sovereignDefense.ebpf_ssh_title')}
                    </div>
                    <label className="block text-[11px] text-white/55">
                      {t('pages.sovereignDefense.ebpf_ssh_host')}
                      <input type="text" value={params.chronos.ebpf_ssh_host}
                        onChange={(e) => setP('chronos', 'ebpf_ssh_host', e.target.value)}
                        className="mt-0.5 w-full rounded bg-black/40 border border-white/10 px-2 py-1.5 text-xs font-mono" />
                    </label>
                    <div className="grid grid-cols-2 gap-2">
                      <label className="block text-[11px] text-white/55">
                        {t('pages.sovereignDefense.ebpf_ssh_user')}
                        <input type="text" value={params.chronos.ebpf_ssh_user}
                          onChange={(e) => setP('chronos', 'ebpf_ssh_user', e.target.value)}
                          className="mt-0.5 w-full rounded bg-black/40 border border-white/10 px-2 py-1.5 text-xs" />
                      </label>
                      <label className="block text-[11px] text-white/55">
                        {t('pages.sovereignDefense.ebpf_ssh_port')}
                        <input type="number" value={params.chronos.ebpf_ssh_port}
                          onChange={(e) => setP('chronos', 'ebpf_ssh_port', e.target.value)}
                          className="mt-0.5 w-full rounded bg-black/40 border border-white/10 px-2 py-1.5 text-xs" />
                      </label>
                    </div>
                    <label className="block text-[11px] text-white/55">
                      {t('pages.sovereignDefense.ebpf_ssh_key_pem')}
                      <textarea rows={3} value={params.chronos.ebpf_ssh_key_pem}
                        onChange={(e) => setP('chronos', 'ebpf_ssh_key_pem', e.target.value)}
                        placeholder="-----BEGIN OPENSSH PRIVATE KEY-----"
                        className="mt-0.5 w-full rounded bg-black/50 border border-white/10 px-2 py-1.5 text-[10px] font-mono text-emerald-200/80" />
                    </label>
                    <label className="block text-[11px] text-white/45">
                      {t('pages.sovereignDefense.ebpf_ssh_key_path')}
                      <input type="text" value={params.chronos.ebpf_ssh_key_path}
                        onChange={(e) => setP('chronos', 'ebpf_ssh_key_path', e.target.value)}
                        className="mt-0.5 w-full rounded bg-black/40 border border-white/10 px-2 py-1.5 text-xs font-mono" />
                    </label>
                  </div>
                  <label className="flex items-center gap-2 text-xs text-white/70">
                    <input type="checkbox" checked={params.chronos.auto_freeze} onChange={(e) => setP('chronos', 'auto_freeze', e.target.checked)} />
                    {t('pages.sovereignDefense.auto_freeze')}
                  </label>
                  <label className="flex items-center gap-2 text-xs text-white/70">
                    <input type="checkbox" checked={params.chronos.deploy_ebpf} onChange={(e) => setP('chronos', 'deploy_ebpf', e.target.checked)} />
                    {t('pages.sovereignDefense.deploy_ebpf')}
                  </label>
                </motion.div>
              )}
              {tab === 'liquid' && (
                <motion.div key="liquid-params" initial={{ opacity: 0 }} animate={{ opacity: 1 }} className="space-y-2">
                  {['rotation_step_secs', 'port_pool_min', 'port_pool_max'].map((k) => (
                    <label key={k} className="block text-[10px] font-mono text-white/50">
                      {k}
                      <input
                        type="number"
                        value={params.liquid[k]}
                        onChange={(e) => setP('liquid', k, e.target.value)}
                        className="mt-0.5 w-full rounded bg-black/40 border border-white/10 px-2 py-1.5 text-xs"
                      />
                    </label>
                  ))}
                  <button
                    type="button"
                    onClick={rotateLiquid}
                    className="w-full mt-2 py-2 rounded-lg border border-cyan-500/40 text-cyan-200 text-xs font-mono hover:bg-cyan-500/10"
                  >
                    {t('pages.sovereignDefense.force_rotate')}
                  </button>
                </motion.div>
              )}
              {tab === 'cognitive' && (
                <motion.div key="cognitive-params" initial={{ opacity: 0 }} animate={{ opacity: 1 }} className="space-y-2">
                  <label className="block text-[10px] font-mono text-white/50">
                    min_bot_score
                    <input type="range" min="0.1" max="0.95" step="0.05" value={params.cognitive.min_bot_score}
                      onChange={(e) => setP('cognitive', 'min_bot_score', e.target.value)} className="w-full" />
                    <span className="text-cyan-300">{params.cognitive.min_bot_score}</span>
                  </label>
                  <label className="block text-[10px] font-mono text-white/50">
                    poison_variants
                    <textarea rows={2} value={params.cognitive.poison_variants}
                      onChange={(e) => setP('cognitive', 'poison_variants', e.target.value)}
                      className="mt-0.5 w-full rounded bg-black/40 border border-white/10 px-2 py-1.5 text-xs font-mono" />
                  </label>
                </motion.div>
              )}
            </AnimatePresence>
          </div>

          {liquid && (
            <div className="rounded-xl border border-cyan-500/20 bg-black/30 p-3 font-mono text-[10px] text-cyan-200/80 space-y-1">
              <p className="text-white/40 uppercase">{t('pages.sovereignDefense.routing_token')}</p>
              <p className="text-lg text-cyan-300">{liquid.routing_code}</p>
              <p>{liquid.internal_ip}:{liquid.internal_port}</p>
              <p className="text-white/35">{liquid.service_fingerprint}</p>
              <p className="text-white/25">{t('pages.sovereignDefense.epoch_expires', { t: liquid.expires_at })}</p>
            </div>
          )}

          <Link to="/agents" className="block text-center text-[11px] font-mono text-white/40 hover:text-cyan-400">
            {t('pages.sovereignDefense.agent_link')}
          </Link>
        </div>

        <div className="xl:col-span-8 space-y-6">
          {tab === 'chronos' && chronosEvents.length > 0 && (
            <div className="rounded-2xl border border-violet-500/20 bg-black/30 p-4 max-h-56 overflow-auto">
              <h3 className="text-sm font-semibold text-violet-200 mb-2">{t('pages.sovereignDefense.chronos_feed')}</h3>
              {chronosEvents.slice(0, 15).map((e) => (
                <div key={e.id} className="text-[11px] font-mono py-1 border-b border-white/5 flex justify-between">
                  <span className="text-white/70">{e.event_type} · {e.process_name || '—'}</span>
                  <span className="text-violet-300">{e.action_taken || ''}</span>
                </div>
              ))}
            </div>
          )}

          {tab === 'cognitive' && (
            <div className="grid md:grid-cols-2 gap-3">
              <div className="rounded-2xl border border-amber-500/20 bg-black/30 p-4 max-h-64 overflow-auto">
                <h3 className="text-sm font-semibold text-amber-200 mb-2">{t('pages.sovereignDefense.poison_lib')}</h3>
                {poisonLib.map((p) => (
                  <div key={p.id} className="text-[10px] font-mono py-2 border-b border-white/5">
                    <span className="text-amber-300">{p.variant}</span>
                    <span className="text-white/30 ml-2">{p.id}</span>
                  </div>
                ))}
              </div>
              <div className="rounded-2xl border border-amber-500/20 bg-black/30 p-4 max-h-64 overflow-auto">
                <h3 className="text-sm font-semibold text-amber-200 mb-2">{t('pages.sovereignDefense.cognitive_feed')}</h3>
                {cognitiveSessions.slice(0, 12).map((s) => (
                  <div key={s.id} className="text-[10px] font-mono py-1 border-b border-white/5 flex justify-between">
                    <span>{Math.round((s.bot_score || 0) * 100)}% · {s.poison_variant}</span>
                    <span className="text-white/35">{s.response_status}</span>
                  </div>
                ))}
              </div>
            </div>
          )}

          <WeissmanFindingsPanel
            findings={filteredFindings}
            searchQuery={searchQuery}
            onSearchChange={setSearchQuery}
            title={t('pages.sovereignDefense.findings', { engine: engine?.label || engineId })}
            emptyMessage={t('pages.sovereignDefense.no_findings')}
          />
        </div>
      </div>
    </PageShell>
  )
}
