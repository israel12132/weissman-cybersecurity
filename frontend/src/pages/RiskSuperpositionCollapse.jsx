import { useCommandCenterScan } from '../hooks/useCommandCenterScan'
import { useSyncHubScanParams } from '../hooks/useLaunchEngineScan'
import React, { useCallback, useEffect, useMemo, useRef, useState } from 'react'
import { Link } from 'react-router-dom'
import { motion } from 'framer-motion'
import { useTranslation } from 'react-i18next'
import PageShell from './PageShell'
import ShellScanActions from '../components/engine/ShellScanActions'
import WeissmanFindingsPanel from '../components/engine/WeissmanFindingsPanel'
import { useWeissmanEnginePage, applyHistoryFindings } from '../hooks/useWeissmanEnginePage'
import { apiFetch } from '../lib/apiBase'
import { ENGINES_BY_ID } from '../lib/enginesRegistry'

const ENGINE_ID = 'risk_superposition_collapse'

const FUSION_MODES = ['hybrid', 'noisy_or', 'log_odds']
const DEFAULT_GOALS = 'impact:objective,access:crown_jewel,data:db_read'

const DEFAULT_PARAMS = {
  weak_signal_threshold: '4.0',
  collapsed_belief_threshold: '0.55',
  min_corroboration_engines: '2',
  max_clusters: '500',
  max_findings: '1000',
  fusion_mode: 'hybrid',
  temporal_decay_halflife_hours: '168',
  kev_belief_boost: '0.15',
  member_count_boost: '0.05',
  max_fusion_findings: '20',
  max_graph_paths: '5',
  max_planner_expansions: '50000',
  planner_goals: DEFAULT_GOALS,
  attack_path_top_k: '10',
  posture_penalty_per_chain: '12',
  min_weak_clusters_for_collapse: '1',
  include_attack_paths: true,
  include_belief_fusion: true,
  include_strips_collapse: true,
  include_toxic_combinations: true,
  include_temporal_correlation: true,
  include_financial_ale: true,
  require_weak_for_collapse: false,
  emit_choke_points: true,
}

const MIN_CLUSTERS_AUTO = 2
const AUTO_RUN_KEY = 'weissman_superposition_auto_run'

const PRESETS = {
  conservative: {
    collapsed_belief_threshold: '0.70',
    min_corroboration_engines: '3',
    weak_signal_threshold: '3.0',
    require_weak_for_collapse: true,
    fusion_mode: 'noisy_or',
  },
  balanced: { ...DEFAULT_PARAMS },
  aggressive: {
    collapsed_belief_threshold: '0.40',
    min_corroboration_engines: '2',
    weak_signal_threshold: '5.0',
    require_weak_for_collapse: false,
    fusion_mode: 'hybrid',
    max_fusion_findings: '30',
    max_graph_paths: '10',
  },
}

function ReadinessRow({ ok, label, detail }) {
  return (
    <div className="flex items-start gap-2 text-[11px] font-mono">
      <span className={ok ? 'text-emerald-400' : 'text-amber-400'} aria-hidden>{ok ? '✓' : '○'}</span>
      <div>
        <span className={ok ? 'text-[var(--text-primary)]' : 'text-[var(--text-tertiary)]'}>{label}</span>
        {detail && <p className="text-[var(--text-muted)] text-[10px] mt-0.5">{detail}</p>}
      </div>
    </div>
  )
}

function numOr(v, d) {
  const n = Number(v)
  return Number.isFinite(n) ? n : d
}

function buildScanBody(params, clientId, target) {
  return {
    engine: ENGINE_ID,
    client_id: Number(clientId),
    target: (target || '').trim(),
    timeout: 180,
    weak_signal_threshold: numOr(params.weak_signal_threshold, 4),
    collapsed_belief_threshold: numOr(params.collapsed_belief_threshold, 0.55),
    min_corroboration_engines: numOr(params.min_corroboration_engines, 2),
    max_clusters: numOr(params.max_clusters, 500),
    max_findings: numOr(params.max_findings, 1000),
    fusion_mode: params.fusion_mode,
    temporal_decay_halflife_hours: numOr(params.temporal_decay_halflife_hours, 168),
    kev_belief_boost: numOr(params.kev_belief_boost, 0.15),
    member_count_boost: numOr(params.member_count_boost, 0.05),
    max_fusion_findings: numOr(params.max_fusion_findings, 20),
    max_graph_paths: numOr(params.max_graph_paths, 5),
    max_planner_expansions: numOr(params.max_planner_expansions, 50000),
    planner_goals: params.planner_goals,
    attack_path_top_k: numOr(params.attack_path_top_k, 10),
    posture_penalty_per_chain: numOr(params.posture_penalty_per_chain, 12),
    min_weak_clusters_for_collapse: numOr(params.min_weak_clusters_for_collapse, 1),
    include_attack_paths: !!params.include_attack_paths,
    include_belief_fusion: !!params.include_belief_fusion,
    include_strips_collapse: !!params.include_strips_collapse,
    include_toxic_combinations: !!params.include_toxic_combinations,
    include_temporal_correlation: !!params.include_temporal_correlation,
    include_financial_ale: !!params.include_financial_ale,
    require_weak_for_collapse: !!params.require_weak_for_collapse,
    emit_choke_points: !!params.emit_choke_points,
  }
}

function postureFromFindings(findings) {
  const grade = findings.find((f) => {
    const t = String(f?.type || f?.title || '').toLowerCase()
    return t.includes('posture') || String(f?.title || '').includes('Superposition posture')
  })
  const ev = grade?.evidence || {}
  return {
    score: Number(ev.posture_score ?? grade?.evidence?.posture_score ?? 0),
    grade: String(ev.posture_grade || '—'),
    chains: Number(ev.collapse_chains ?? 0),
    clusters: Number(ev.cluster_count ?? 0),
    confidence: Number(grade?.confidence ?? 0),
  }
}

function CollapseChainCard({ finding }) {
  const ev = finding?.evidence || {}
  const chain = ev.attack_chain
  const steps = chain?.steps || []
  return (
    <div className="rounded-xl border border-violet-500/30 bg-violet-950/20 p-4 space-y-3">
      <div className="flex items-start justify-between gap-3">
        <div>
          <p className="text-[11px] font-mono text-violet-300/80 uppercase tracking-wider">STRIPS collapse</p>
          <h4 className="text-sm font-semibold text-white mt-1">{finding.title}</h4>
        </div>
        <span className="text-xs font-mono px-2 py-1 rounded-md bg-violet-500/20 text-violet-200 border border-violet-500/30">
          {Math.round((finding.confidence || 0) * 100)}%
        </span>
      </div>
      {ev.mitre_path && (
        <p className="text-[11px] font-mono text-cyan-300/90 break-all">{String(ev.mitre_path)}</p>
      )}
      {steps.length > 0 && (
        <ol className="space-y-1.5 text-[11px] font-mono text-[var(--text-secondary)]">
          {steps.map((s, i) => (
            <li key={i} className="flex gap-2">
              <span className="text-violet-400 shrink-0">{i + 1}.</span>
              <span>{s.name} <span className="text-[var(--text-muted)]">({s.mitre})</span></span>
            </li>
          ))}
        </ol>
      )}
      {ev.weak_signals && (
        <p className="text-[10px] text-amber-300/80 border-t border-[var(--border-subtle)] pt-2">
          Weak signals: {String(ev.weak_signals)}
        </p>
      )}
    </div>
  )
}

function ParamSection({ title, children, defaultOpen = true }) {
  const [open, setOpen] = useState(defaultOpen)
  return (
    <div className="rounded-xl border border-[var(--border-default)] bg-[var(--table-surface)] overflow-hidden">
      <button
        type="button"
        onClick={() => setOpen((o) => !o)}
        className="w-full flex items-center justify-between px-4 py-3 text-left hover:bg-[var(--row-hover-bg)] transition-colors"
      >
        <span className="text-xs font-semibold text-[var(--text-primary)] uppercase tracking-wider">{title}</span>
        <span className="text-[var(--text-muted)] text-sm">{open ? '−' : '+'}</span>
      </button>
      {open && <div className="px-4 pb-4 space-y-3 border-t border-[var(--border-subtle)] pt-3">{children}</div>}
    </div>
  )
}

function Field({ label, hint, children }) {
  return (
    <label className="block space-y-1">
      <span className="text-[11px] font-mono text-[var(--text-tertiary)]">{label}</span>
      {children}
      {hint && <span className="text-[10px] text-[var(--text-muted)] block">{hint}</span>}
    </label>
  )
}

export default function RiskSuperpositionCollapse() {
  const { t } = useTranslation()
  const engine = ENGINES_BY_ID[ENGINE_ID]
  const [params, setParams] = useState(DEFAULT_PARAMS)
  useSyncHubScanParams(ENGINE_ID, params)
  const [clients, setClients] = useState([])
  const [clientId, setClientId] = useState('')
  const { postScan } = useCommandCenterScan(clientId)
  const [target, setTarget] = useState('')
  const [findings, setFindings] = useState([])
  const [clusters, setClusters] = useState([])
  const [clustersLoading, setClustersLoading] = useState(false)
  const [runState, setRunState] = useState({ running: false, msg: '' })
  const [jobId, setJobId] = useState('')
  const [lastUpdated, setLastUpdated] = useState(null)
  const [autoRunEnabled, setAutoRunEnabled] = useState(() => {
    try {
      return sessionStorage.getItem(AUTO_RUN_KEY) !== '0'
    } catch {
      return true
    }
  })
  const [showPayload, setShowPayload] = useState(false)
  const autoRanRef = useRef(false)

  const readiness = useMemo(() => ({
    hasClient: Boolean(clientId),
    hasTarget: Boolean(target.trim()),
    enoughClusters: clusters.length >= MIN_CLUSTERS_AUTO,
    ready: Boolean(clientId) && Boolean(target.trim()) && clusters.length >= MIN_CLUSTERS_AUTO,
  }), [clientId, target, clusters.length])

  const scanPreview = useMemo(() => {
    if (!clientId || !target.trim()) return null
    return buildScanBody(params, clientId, target)
  }, [params, clientId, target])

  const {
    searchQuery,
    setSearchQuery,
    filteredFindings,
    refreshFromHistory,
    historyLoading,
  } = useWeissmanEnginePage(ENGINE_ID, findings, {
    csvPrefix: 'weissman-superposition-collapse',
    haystackFn: (f) => `${f.title} ${f.type} ${f.description} ${f.severity}`,
  })

  const setP = useCallback((key, val) => {
    setParams((prev) => ({ ...prev, [key]: val }))
  }, [])

  const applyPreset = useCallback((name) => {
    const preset = PRESETS[name]
    if (!preset) return
    setParams((prev) => ({ ...prev, ...preset }))
  }, [])

  const toggleAutoRun = useCallback((enabled) => {
    setAutoRunEnabled(enabled)
    try {
      sessionStorage.setItem(AUTO_RUN_KEY, enabled ? '1' : '0')
    } catch { /* ignore */ }
  }, [])

  const runCollapse = useCallback(async (isAuto = false) => {
    if (!clientId) {
      setRunState({ running: false, msg: t('pages.superpositionCollapse.select_client') })
      return
    }
    if (!target.trim()) {
      setRunState({ running: false, msg: t('pages.superpositionCollapse.target_required') })
      return
    }
    if (!readiness.enoughClusters && !isAuto) {
      setRunState({ running: false, msg: t('pages.superpositionCollapse.need_clusters', { min: MIN_CLUSTERS_AUTO }) })
      return
    }
    setRunState({ running: true, msg: isAuto ? t('pages.superpositionCollapse.auto_queueing') : t('pages.superpositionCollapse.queueing') })
    if (!isAuto) setFindings([])
    try {
      const { ok, data: d, status } = await postScan(buildScanBody(params, clientId, target))
      if (!ok) {
        setRunState({ running: false, msg: d.detail || `HTTP ${status}` })
        return
      }
      setJobId(d.job_id || '')
      setRunState({
        running: true,
        msg: isAuto
          ? t('pages.superpositionCollapse.auto_queued', { jobId: d.job_id })
          : t('pages.superpositionCollapse.queued', { jobId: d.job_id }),
      })
    } catch (e) {
      setRunState({ running: false, msg: e?.message || 'Network error' })
    }
  }, [clientId, target, readiness.enoughClusters, params, t])

  useEffect(() => {
    apiFetch('/api/clients')
      .then((r) => (r.ok ? r.json() : []))
      .then((d) => { if (Array.isArray(d)) setClients(d) })
      .catch(() => {})
  }, [])

  useEffect(() => {
    if (!clientId) return
    const c = clients.find((x) => String(x.id) === String(clientId))
    if (!c) return
    let domains = c.domains
    if (typeof domains === 'string') {
      try { domains = JSON.parse(domains) } catch { domains = [] }
    }
    const first = Array.isArray(domains) ? domains[0] : ''
    if (first) setTarget(first.startsWith('http') ? first : `https://${first}`)
  }, [clientId, clients])

  const loadClusters = useCallback(async () => {
    if (!clientId) return
    setClustersLoading(true)
    try {
      const r = await apiFetch(`/api/findings/clusters?limit=40&client_id=${encodeURIComponent(clientId)}`)
      const d = await r.json().catch(() => ({}))
      if (r.ok && Array.isArray(d?.clusters)) setClusters(d.clusters)
      else if (r.ok && Array.isArray(d?.items)) setClusters(d.items)
      else setClusters([])
    } finally {
      setClustersLoading(false)
    }
  }, [clientId])

  useEffect(() => {
    loadClusters()
  }, [loadClusters])

  // Auto-run once per session when prerequisites are live (clusters ≥ 2, client, target).
  useEffect(() => {
    if (!autoRunEnabled || autoRanRef.current || runState.running) return
    if (!readiness.ready || clustersLoading) return
    autoRanRef.current = true
    runCollapse(true)
  }, [autoRunEnabled, readiness.ready, clustersLoading, runState.running, runCollapse])

  useEffect(() => {
    refreshFromHistory().then(async (run) => {
      if (applyHistoryFindings(run, setFindings, { setLastUpdated, setJobId })) return
      const fr = await apiFetch(`/api/engines/history/${ENGINE_ID}?limit=1`)
      const hist = await fr.json().catch(() => ({}))
      if (Array.isArray(hist?.findings) && hist.findings.length) {
        setFindings(hist.findings)
      }
    })
  }, [refreshFromHistory])

  const posture = useMemo(() => postureFromFindings(findings), [findings])
  const collapseFindings = useMemo(
    () => filteredFindings.filter((f) => {
      const title = String(f?.title || '').toLowerCase()
      return title.includes('collapse') || title.includes('toxic') || title.includes('fusion')
    }),
    [filteredFindings],
  )
  const otherFindings = useMemo(
    () => filteredFindings.filter((f) => !collapseFindings.includes(f)),
    [filteredFindings, collapseFindings],
  )

  const gradeColor = posture.score <= 40 ? '#ef4444' : posture.score <= 70 ? '#f59e0b' : '#22c55e'

  useEffect(() => {
    if (!jobId || !runState.running) return undefined
    const iv = setInterval(async () => {
      const r = await apiFetch(`/api/jobs/${encodeURIComponent(jobId)}`)
      const d = await r.json().catch(() => null)
      if (!r.ok || !d) return
      const status = String(d.status || '').toLowerCase()
      if (status === 'completed') {
        const raw = d.result_json || d.result || {}
        const jobFindings = Array.isArray(raw.findings) ? raw.findings : []
        if (jobFindings.length > 0) {
          setFindings(jobFindings)
        } else {
          const fr = await apiFetch(`/api/engines/history/${ENGINE_ID}?limit=1`)
          const hist = await fr.json().catch(() => ({}))
          setFindings(Array.isArray(hist?.findings) ? hist.findings : [])
        }
        setLastUpdated(new Date().toISOString())
        setRunState({ running: false, msg: t('pages.superpositionCollapse.complete') })
        loadClusters()
      } else if (status === 'failed' || status === 'dead') {
        setRunState({ running: false, msg: d.error || status })
      }
    }, 2500)
    return () => clearInterval(iv)
  }, [jobId, runState.running, loadClusters, t])

  return (
    <PageShell
      hideHubParams
      engineId={ENGINE_ID}
      title={t('pages.superpositionCollapse.title')}
      subtitle={t('pages.superpositionCollapse.subtitle')}
      badge={t('pages.superpositionCollapse.badge')}
      badgeColor="#a855f7"
      icon="◈"
      maxWidth="max-w-[1600px]"
      syncAt={lastUpdated}
      evidence={t('pages.superpositionCollapse.evidence_notice')}
      breadcrumbs={[
        { label: t('nav.engines'), to: '/engine-matrix' },
        { label: engine?.label || ENGINE_ID, to: `/engines/${ENGINE_ID}` },
        { label: t('pages.superpositionCollapse.breadcrumb') },
      ]}
      actions={(
        <ShellScanActions
          running={runState.running}
          onRun={() => runCollapse(false)}
          onRefresh={refreshFromHistory}
          refreshLoading={historyLoading}
          runLabel={t('pages.superpositionCollapse.run')}
        />
      )}
    >
      <div className="rounded-xl border border-emerald-500/20 bg-emerald-950/15 px-4 py-3 mb-6 text-[11px] text-emerald-100/90 font-mono leading-relaxed">
        {t('pages.superpositionCollapse.security_notice')}
      </div>

      <div className="grid grid-cols-1 xl:grid-cols-12 gap-6">
        {/* Controls */}
        <div className="xl:col-span-4 space-y-4">
          <div className="rounded-2xl border border-[var(--border-default)] bg-gradient-to-b from-violet-950/30 to-black/40 p-4 space-y-4">
            <h3 className="text-sm font-semibold text-white">{t('pages.superpositionCollapse.controls')}</h3>

            <div className="rounded-lg border border-[var(--border-default)] bg-[var(--bg-2)] p-3 space-y-2">
              <p className="text-[10px] uppercase tracking-wider text-violet-300/80 font-mono">
                {t('pages.superpositionCollapse.readiness_title')}
              </p>
              <ReadinessRow ok={readiness.hasClient} label={t('pages.superpositionCollapse.ready_client')} />
              <ReadinessRow ok={readiness.hasTarget} label={t('pages.superpositionCollapse.ready_target')} />
              <ReadinessRow
                ok={readiness.enoughClusters}
                label={t('pages.superpositionCollapse.ready_clusters')}
                detail={t('pages.superpositionCollapse.ready_clusters_detail', { count: clusters.length, min: MIN_CLUSTERS_AUTO })}
              />
              {readiness.ready && (
                <p className="text-[10px] text-emerald-400 pt-1">{t('pages.superpositionCollapse.ready_go')}</p>
              )}
            </div>

            <div className="flex flex-wrap gap-2">
              {['conservative', 'balanced', 'aggressive'].map((p) => (
                <button
                  key={p}
                  type="button"
                  onClick={() => applyPreset(p)}
                  className="text-[10px] font-mono px-2.5 py-1.5 rounded-lg border border-violet-500/30 text-violet-200 hover:bg-violet-500/15 transition-colors"
                >
                  {t(`pages.superpositionCollapse.preset_${p}`)}
                </button>
              ))}
            </div>

            <label className="flex items-center gap-2 text-[11px] text-[var(--text-secondary)] cursor-pointer select-none">
              <input
                type="checkbox"
                checked={autoRunEnabled}
                onChange={(e) => toggleAutoRun(e.target.checked)}
                className="rounded border-[var(--border-strong)]"
              />
              {t('pages.superpositionCollapse.auto_run_label')}
            </label>

            <Field label={t('pages.superpositionCollapse.client')}>
              <select
                value={clientId}
                onChange={(e) => setClientId(e.target.value)}
                className="w-full rounded-lg bg-[var(--bg-3)] border border-[var(--border-strong)] px-3 py-2 text-sm text-white"
              >
                <option value="">{t('pages.superpositionCollapse.select_client')}</option>
                {clients.map((c) => (
                  <option key={c.id} value={c.id}>{c.name || c.id}</option>
                ))}
              </select>
            </Field>
            <Field label={t('pages.superpositionCollapse.target')}>
              <input
                type="url"
                value={target}
                onChange={(e) => setTarget(e.target.value)}
                className="w-full rounded-lg bg-[var(--bg-3)] border border-[var(--border-strong)] px-3 py-2 text-sm text-white font-mono"
                placeholder="https://"
              />
            </Field>
            {runState.msg && (
              <p className="text-[11px] font-mono text-cyan-300/90">{runState.msg}</p>
            )}
          </div>

          <ParamSection title={t('pages.superpositionCollapse.section_fusion')}>
            <Field label={t('pages.superpositionCollapse.fusion_mode')} hint={t('pages.superpositionCollapse.fusion_mode_hint')}>
              <select
                value={params.fusion_mode}
                onChange={(e) => setP('fusion_mode', e.target.value)}
                className="w-full rounded-lg bg-[var(--bg-3)] border border-[var(--border-strong)] px-3 py-2 text-sm"
              >
                {FUSION_MODES.map((m) => (
                  <option key={m} value={m}>{m}</option>
                ))}
              </select>
            </Field>
            <Field label={t('pages.superpositionCollapse.belief_threshold')}>
              <input type="range" min="0.1" max="0.95" step="0.01" value={params.collapsed_belief_threshold}
                onChange={(e) => setP('collapsed_belief_threshold', e.target.value)} className="w-full" />
              <span className="text-xs font-mono text-violet-300">{params.collapsed_belief_threshold}</span>
            </Field>
            <Field label={t('pages.superpositionCollapse.weak_threshold')}>
              <input type="number" min="0" max="10" step="0.5" value={params.weak_signal_threshold}
                onChange={(e) => setP('weak_signal_threshold', e.target.value)}
                className="w-full rounded-lg bg-[var(--bg-3)] border border-[var(--border-strong)] px-3 py-2 text-sm" />
            </Field>
            <Field label={t('pages.superpositionCollapse.min_engines')}>
              <input type="number" min="1" max="20" value={params.min_corroboration_engines}
                onChange={(e) => setP('min_corroboration_engines', e.target.value)}
                className="w-full rounded-lg bg-[var(--bg-3)] border border-[var(--border-strong)] px-3 py-2 text-sm" />
            </Field>
            <Field label={t('pages.superpositionCollapse.decay_halflife')}>
              <input type="number" min="0" max="8760" value={params.temporal_decay_halflife_hours}
                onChange={(e) => setP('temporal_decay_halflife_hours', e.target.value)}
                className="w-full rounded-lg bg-[var(--bg-3)] border border-[var(--border-strong)] px-3 py-2 text-sm" />
            </Field>
          </ParamSection>

          <ParamSection title={t('pages.superpositionCollapse.section_modules')} defaultOpen={false}>
            {[
              ['include_belief_fusion', t('pages.superpositionCollapse.mod_fusion')],
              ['include_toxic_combinations', t('pages.superpositionCollapse.mod_toxic')],
              ['include_strips_collapse', t('pages.superpositionCollapse.mod_strips')],
              ['include_temporal_correlation', t('pages.superpositionCollapse.mod_temporal')],
              ['include_attack_paths', t('pages.superpositionCollapse.mod_graph')],
              ['include_financial_ale', t('pages.superpositionCollapse.mod_financial')],
              ['require_weak_for_collapse', t('pages.superpositionCollapse.mod_require_weak')],
              ['emit_choke_points', t('pages.superpositionCollapse.mod_choke')],
            ].map(([key, label]) => (
              <label key={key} className="flex items-center gap-2 text-sm text-[var(--text-secondary)] cursor-pointer">
                <input
                  type="checkbox"
                  checked={!!params[key]}
                  onChange={(e) => setP(key, e.target.checked)}
                  className="rounded border-[var(--border-strong)]"
                />
                {label}
              </label>
            ))}
          </ParamSection>

          <ParamSection title={t('pages.superpositionCollapse.section_limits')} defaultOpen={false}>
            {[
              ['max_clusters', '500'],
              ['max_findings', '1000'],
              ['max_fusion_findings', '20'],
              ['max_graph_paths', '5'],
              ['max_planner_expansions', '50000'],
              ['attack_path_top_k', '10'],
              ['posture_penalty_per_chain', '12'],
              ['kev_belief_boost', '0.15'],
              ['member_count_boost', '0.05'],
              ['min_weak_clusters_for_collapse', '1'],
            ].map(([key]) => (
              <Field key={key} label={key}>
                <input
                  type="text"
                  value={params[key]}
                  onChange={(e) => setP(key, e.target.value)}
                  className="w-full rounded-lg bg-[var(--bg-3)] border border-[var(--border-strong)] px-3 py-2 text-sm font-mono"
                />
              </Field>
            ))}
            <Field label={t('pages.superpositionCollapse.planner_goals')}>
              <textarea
                rows={3}
                value={params.planner_goals}
                onChange={(e) => setP('planner_goals', e.target.value)}
                className="w-full rounded-lg bg-[var(--bg-3)] border border-[var(--border-strong)] px-3 py-2 text-sm font-mono"
              />
            </Field>
          </ParamSection>

          {scanPreview && (
            <div className="rounded-xl border border-[var(--border-default)] bg-[var(--table-surface)] overflow-hidden">
              <button
                type="button"
                onClick={() => setShowPayload((s) => !s)}
                className="w-full px-4 py-2 text-left text-[10px] font-mono text-[var(--text-tertiary)] hover:bg-[var(--row-hover-bg)]"
              >
                {showPayload ? '▼' : '▶'} {t('pages.superpositionCollapse.payload_preview')}
              </button>
              {showPayload && (
                <pre className="px-4 pb-3 text-[10px] font-mono text-cyan-300/90 overflow-auto max-h-48">
                  {JSON.stringify(scanPreview, null, 2)}
                </pre>
              )}
            </div>
          )}

          <Link
            to={`/engines/${ENGINE_ID}`}
            className="block text-center text-[11px] font-mono text-[var(--text-muted)] hover:text-cyan-400 transition-colors"
          >
            {t('pages.superpositionCollapse.generic_engine_page')}
          </Link>
        </div>

        {/* Main panel */}
        <div className="xl:col-span-8 space-y-6">
          <motion.div
            initial={{ opacity: 0, y: 8 }}
            animate={{ opacity: 1, y: 0 }}
            className="rounded-2xl border border-violet-500/25 bg-gradient-to-br from-violet-950/40 via-black/50 to-cyan-950/20 p-6"
          >
            <div className="flex flex-wrap items-center gap-6 justify-between">
              <div>
                <p className="text-[10px] font-mono uppercase tracking-widest text-violet-300/70">
                  {t('pages.superpositionCollapse.posture_label')}
                </p>
                <div className="flex items-baseline gap-3 mt-1">
                  <span className="text-5xl font-bold font-mono" style={{ color: gradeColor }}>
                    {posture.grade !== '—' ? posture.grade : '…'}
                  </span>
                  <span className="text-2xl font-mono text-[var(--text-tertiary)]">{posture.score}/100</span>
                </div>
                <p className="text-xs text-[var(--text-muted)] mt-2 font-mono">
                  {t('pages.superpositionCollapse.posture_meta', {
                    chains: posture.chains,
                    clusters: posture.clusters || clusters.length,
                  })}
                </p>
              </div>
              <div className="flex gap-4 text-center">
                <div className="px-4 py-2 rounded-xl bg-[var(--bg-2)] border border-[var(--border-default)]">
                  <p className="text-2xl font-mono text-cyan-300">{clusters.length}</p>
                  <p className="text-[10px] text-[var(--text-muted)] uppercase">{t('pages.superpositionCollapse.live_clusters')}</p>
                </div>
                <div className="px-4 py-2 rounded-xl bg-[var(--bg-2)] border border-[var(--border-default)]">
                  <p className="text-2xl font-mono text-amber-300">{collapseFindings.length}</p>
                  <p className="text-[10px] text-[var(--text-muted)] uppercase">{t('pages.superpositionCollapse.collapses')}</p>
                </div>
              </div>
            </div>
          </motion.div>

          <div className="rounded-2xl border border-[var(--border-default)] bg-[var(--table-surface)] p-4">
            <div className="flex items-center justify-between mb-3">
              <h3 className="text-sm font-semibold text-white">{t('pages.superpositionCollapse.cluster_feed')}</h3>
              <button type="button" onClick={loadClusters} disabled={clustersLoading}
                className="text-[10px] font-mono text-cyan-400 hover:underline disabled:opacity-50">
                {clustersLoading ? '…' : t('pages.superpositionCollapse.refresh_clusters')}
              </button>
            </div>
            {clusters.length === 0 ? (
              <p className="text-xs text-[var(--text-muted)] font-mono">{t('pages.superpositionCollapse.no_clusters')}</p>
            ) : (
              <div className="max-h-48 overflow-auto space-y-1.5">
                {clusters.slice(0, 20).map((c) => (
                  <div key={c.id} className="flex items-center justify-between text-[11px] font-mono py-1.5 px-2 rounded-lg bg-[var(--row-hover-bg)]">
                    <span className="text-[var(--text-secondary)] truncate flex-1">{c.title || c.vuln_signature}</span>
                    <span className="text-violet-300 mx-2">{c.member_count}×</span>
                    <span className={`uppercase text-[10px] ${
                      c.max_severity === 'critical' ? 'text-red-400' :
                      c.max_severity === 'high' ? 'text-orange-400' : 'text-[var(--text-tertiary)]'
                    }`}>{c.max_severity}</span>
                  </div>
                ))}
              </div>
            )}
          </div>

          {collapseFindings.length > 0 && (
            <div className="space-y-3">
              <h3 className="text-sm font-semibold text-violet-200">{t('pages.superpositionCollapse.collapse_chains')}</h3>
              <div className="grid gap-3 md:grid-cols-2">
                {collapseFindings.slice(0, 8).map((f, i) => (
                  <CollapseChainCard key={i} finding={f} />
                ))}
              </div>
            </div>
          )}

          <WeissmanFindingsPanel
            findings={otherFindings}
            searchQuery={searchQuery}
            onSearchChange={setSearchQuery}
            title={t('pages.superpositionCollapse.all_findings')}
            emptyMessage={t('pages.superpositionCollapse.no_findings')}
          />
        </div>
      </div>
    </PageShell>
  )
}
