import { useCommandCenterScan } from '../hooks/useCommandCenterScan'
import { useHubBodySync } from '../hooks/useLaunchEngineScan'
import { useClientTargetPrefill } from '../hooks/useHubLocalScanParams'
import React, { useState, useEffect, useCallback, useMemo } from 'react'
import { useTranslation } from 'react-i18next'
import { useParams } from 'react-router-dom'
import { motion, AnimatePresence } from 'framer-motion'
import { Loader2, Play, RotateCw, ShieldAlert, ShieldCheck, Trash2 } from 'lucide-react'
import PageShell from './PageShell'
import ShellScanActions from '../components/engine/ShellScanActions'
import WeissmanFindingsPanel from '../components/engine/WeissmanFindingsPanel'
import { useWeissmanEnginePage, applyHistoryFindings } from '../hooks/useWeissmanEnginePage'
import { apiFetch } from '../lib/apiBase'
import { useJobPoll, resolveJobFindings, uiJobStatus } from '../lib/useJobPoll'

const ENGINE = 'digital_twin'
const SIMULATION_SCENARIO_IDS = ['xss', 'sqli', 'mitm', 'cors']

const SCENARIO_META = {
  xss: { mitre: 'T1059.007', color: '#ef4444', risk: 'high' },
  sqli: { mitre: 'T1190', color: '#f97316', risk: 'critical' },
  mitm: { mitre: 'T1557', color: '#f59e0b', risk: 'high' },
  cors: { mitre: 'T1190', color: '#8b5cf6', risk: 'medium' },
}

const RISK_COLOR = { critical: '#ef4444', high: '#f97316', medium: '#f59e0b', low: '#22d3ee' }

const TOGGLES = [
  { key: 'check_xss', labelKey: 'check_xss', defaultVal: true },
  { key: 'check_sqli', labelKey: 'check_sqli', defaultVal: true },
  { key: 'check_mitm', labelKey: 'check_mitm', defaultVal: true },
  { key: 'check_cors', labelKey: 'check_cors', defaultVal: true },
  { key: 'strict_mode', labelKey: 'strict_mode', defaultVal: false },
  { key: 'include_http_cleartext', labelKey: 'include_http_cleartext', defaultVal: true },
  { key: 'canary_only', labelKey: 'canary_only', defaultVal: true },
]

const SUBSCORES = [
  { key: 'transport', labelKey: 'subscore_transport' },
  { key: 'headers', labelKey: 'subscore_headers' },
  { key: 'cors', labelKey: 'subscore_cors' },
  { key: 'injection', labelKey: 'subscore_injection' },
]

const EXPLOIT_STYLE = {
  exploitable: { color: '#fb7185', icon: '☠', labelKey: 'exploit_exploitable' },
  partial: { color: '#fbbf24', icon: '⚠', labelKey: 'exploit_partial' },
  hardening_gaps: { color: '#38bdf8', icon: '◌', labelKey: 'exploit_hardening' },
  hardened: { color: '#34d399', icon: '🛡', labelKey: 'exploit_hardened' },
}

function gradeColor(grade) {
  return {
    'A+': '#34d399', A: '#34d399', 'A-': '#34d399',
    B: '#a3e635', C: '#fbbf24', D: '#fb923c', F: '#fb7185',
  }[grade] || '#fb7185'
}

function isSummary(f) {
  return f && (f.category === 'summary' || typeof f.grade === 'string')
}

function scenarioState(result) {
  if (!result) return 'idle'
  if (result.pending) return 'pending'
  return result.vulnerable ? 'vulnerable' : 'clear'
}

const STATE_META = {
  idle: { color: '#64748b', dot: '#64748b' },
  pending: { color: '#a78bfa', dot: '#a78bfa' },
  vulnerable: { color: '#f43f5e', dot: '#f43f5e' },
  clear: { color: '#34d399', dot: '#34d399' },
}

function SubScoreBar({ label, value }) {
  const v = Math.max(0, Math.min(100, Number(value) || 0))
  const color = v >= 85 ? '#34d399' : v >= 60 ? '#a3e635' : v >= 40 ? '#fbbf24' : '#fb7185'
  return (
    <div>
      <div className="flex items-center justify-between mb-1">
        <span className="text-[10px] font-mono text-[var(--text-tertiary)]">{label}</span>
        <span className="text-[10px] font-mono" style={{ color }}>{v}</span>
      </div>
      <div className="h-1.5 rounded-full bg-white/8 overflow-hidden">
        <div className="h-full rounded-full transition-all duration-500" style={{ width: `${v}%`, backgroundColor: color }} />
      </div>
    </div>
  )
}

function Scorecard({ summary, t }) {
  if (!summary) return null
  const score = summary.score ?? 0
  const grade = summary.grade || '—'
  const color = gradeColor(grade)
  const exploit = EXPLOIT_STYLE[summary.exploitability] || EXPLOIT_STYLE.hardening_gaps
  const subscores = summary.subscores || {}
  const roadmap = Array.isArray(summary.roadmap) ? summary.roadmap : []
  const toxic = summary.toxic_combination || summary.exploitability_reason || ''

  return (
    <motion.div initial={{ opacity: 0, y: 8 }} animate={{ opacity: 1, y: 0 }}
      className="rounded-2xl bg-[var(--bg-2)] backdrop-blur-md border border-[var(--border-default)] p-6 mb-6">
      <div className="flex flex-col lg:flex-row gap-6">
        <div className="flex items-center gap-5">
          <div className="relative w-28 h-28 shrink-0">
            <svg viewBox="0 0 100 100" className="w-full h-full -rotate-90">
              <circle cx="50" cy="50" r="42" fill="none" stroke="rgba(255,255,255,0.06)" strokeWidth="8" />
              <circle cx="50" cy="50" r="42" fill="none" stroke={color} strokeWidth="8"
                strokeDasharray={`${(score / 100) * 264} 264`} strokeLinecap="round" />
            </svg>
            <div className="absolute inset-0 flex flex-col items-center justify-center">
              <span className="text-2xl font-bold" style={{ color }}>{grade}</span>
              <span className="text-[10px] font-mono text-[var(--text-muted)]">{score}/100</span>
            </div>
          </div>
          <div>
            <div className="text-[10px] font-mono uppercase tracking-widest text-[var(--text-muted)] mb-1">
              {t('pages.digitalTwinSimulator.posture_grade')}
            </div>
            <div className="inline-flex items-center gap-2 px-3 py-1.5 rounded-lg border text-xs font-mono"
              style={{ color: exploit.color, borderColor: `${exploit.color}40`, backgroundColor: `${exploit.color}10` }}>
              <span>{exploit.icon}</span>
              <span>{t(`pages.digitalTwinSimulator.${exploit.labelKey}`)}</span>
            </div>
            {toxic && (
              <p className="mt-2 text-[11px] font-mono text-rose-300/80 max-w-md leading-relaxed">{toxic}</p>
            )}
          </div>
        </div>
        <div className="flex-1 grid grid-cols-2 gap-3">
          {SUBSCORES.map((s) => (
            <SubScoreBar key={s.key} label={t(`pages.digitalTwinSimulator.${s.labelKey}`)} value={subscores[s.key]} />
          ))}
        </div>
      </div>
      {roadmap.length > 0 && (
        <div className="mt-5 pt-5 border-t border-[var(--border-subtle)]">
          <div className="text-[10px] font-mono uppercase tracking-widest text-[var(--text-muted)] mb-3">
            {t('pages.digitalTwinSimulator.roadmap_heading')}
          </div>
          <ol className="space-y-2">
            {roadmap.slice(0, 6).map((step, i) => (
              <li key={i} className="flex gap-2 text-[11px] font-mono text-[var(--text-tertiary)] leading-relaxed">
                <span className="text-violet-400 shrink-0">{i + 1}.</span>
                <span>{step}</span>
              </li>
            ))}
          </ol>
        </div>
      )}
    </motion.div>
  )
}

function TwinProfilePanel({ profile, t }) {
  if (!profile) {
    return (
      <p className="text-[11px] font-mono text-[var(--text-disabled)] text-center py-4">
        {t('pages.digitalTwinSimulator.env_empty')}
      </p>
    )
  }
  const sh = profile.security_headers || {}
  const tr = profile.transport || {}
  const cors = profile.cors || {}

  const rows = [
    { label: t('pages.digitalTwinSimulator.profile_server'), value: profile.server || '—' },
    { label: t('pages.digitalTwinSimulator.profile_stack'), value: profile.powered_by || '—' },
    { label: 'HSTS', value: sh.hsts ? `✓ max-age=${sh.hsts_max_age ?? '?'}` : '✕ absent' },
    { label: 'CSP', value: sh.csp ? (sh.csp_unsafe_inline ? '⚠ unsafe-inline' : '✓ present') : '✕ absent' },
    { label: 'CORS', value: cors.present ? cors.acao || 'present' : '—' },
    { label: t('pages.digitalTwinSimulator.profile_cleartext'), value: tr.http_cleartext ? (tr.http_redirects_to_https ? 'HTTP→HTTPS' : '⚠ cleartext') : '✓ HTTPS only' },
  ]

  return (
    <div className="space-y-3">
      {rows.map((r) => (
        <div key={r.label} className="flex justify-between gap-2 text-[11px] font-mono">
          <span className="text-[var(--text-muted)]">{r.label}</span>
          <span className="text-[var(--text-secondary)] truncate text-right">{r.value}</span>
        </div>
      ))}
      {Array.isArray(profile.discovered_paths) && profile.discovered_paths.length > 0 && (
        <div className="pt-2 border-t border-[var(--border-subtle)]">
          <p className="text-[10px] font-mono text-[var(--text-muted)] mb-1">{t('pages.digitalTwinSimulator.profile_paths')}</p>
          <p className="text-[10px] font-mono text-cyan-300/70">{profile.discovered_paths.length} paths</p>
        </div>
      )}
    </div>
  )
}

function ScenarioCard({ scenarioId, result, onRun, running, disabled, t }) {
  const meta = SCENARIO_META[scenarioId]
  const riskColor = RISK_COLOR[meta.risk] ?? '#6b7280'
  const label = t(`pages.digitalTwinSimulator.scenarios.${scenarioId}.label`)
  const description = t(`pages.digitalTwinSimulator.scenarios.${scenarioId}.description`)
  const riskLabel = t(`pages.digitalTwinSimulator.risk_${meta.risk}`)

  const state = scenarioState(result)
  const sm = STATE_META[state]
  const isPending = state === 'pending'
  const hasResult = state === 'vulnerable' || state === 'clear'

  return (
    <motion.div layout initial={{ opacity: 0, y: 8 }} animate={{ opacity: 1, y: 0 }}
      className="rounded-2xl bg-[var(--bg-2)] backdrop-blur-md border border-[var(--border-default)] p-5 space-y-4 hover:border-[var(--border-strong)] transition-all"
      style={state === 'vulnerable' ? { borderColor: `${riskColor}40` } : {}}>
      <div className="flex items-start justify-between gap-3">
        <div className="min-w-0">
          <div className="flex items-center gap-2 mb-1 flex-wrap">
            <h3 className="text-sm font-semibold text-white">{label}</h3>
            <span className="text-[9px] font-mono px-1.5 py-0.5 rounded border uppercase tracking-widest"
              style={{ color: riskColor, borderColor: `${riskColor}40`, backgroundColor: `${riskColor}10` }}>
              {riskLabel}
            </span>
          </div>
          <span className="text-[9px] font-mono text-[var(--text-disabled)] bg-white/5 px-1.5 py-0.5 rounded border border-[var(--border-default)]">
            {meta.mitre}
          </span>
        </div>
        <button type="button" onClick={() => onRun(scenarioId)} disabled={disabled || running || isPending}
          className="shrink-0 inline-flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-[11px] font-mono uppercase border transition-all disabled:opacity-40 disabled:cursor-not-allowed"
          style={{ borderColor: `${riskColor}40`, color: riskColor, backgroundColor: `${riskColor}10` }}>
          {running || isPending ? <Loader2 className="w-3 h-3 animate-spin" />
            : hasResult ? <RotateCw className="w-3 h-3" /> : <Play className="w-3 h-3" />}
          {running ? t('pages.digitalTwinSimulator.simulating')
            : isPending ? t('pages.digitalTwinSimulatostatus_pending')
              : hasResult ? t('pages.digitalTwinSimulator.rerun')
                : t('pages.digitalTwinSimulator.simulate')}
        </button>
      </div>
      <p className="text-[11px] text-[var(--text-muted)] leading-relaxed">{description}</p>
      <div className="pt-3 border-t border-[var(--border-subtle)] space-y-2">
        {state === 'idle' && (
          <p className="text-[10px] font-mono text-[var(--text-disabled)]">{t('pages.digitalTwinSimulator.not_run_hint')}</p>
        )}
        {isPending && (
          <div className="flex items-center gap-2">
            <Loader2 className="w-3.5 h-3.5 animate-spin" style={{ color: sm.color }} />
            <span className="text-xs font-mono" style={{ color: sm.color }}>{t('pages.digitalTwinSimulator.pending_status')}</span>
          </div>
        )}
        {hasResult && (
          <>
            <div className="flex items-center gap-2">
              {state === 'vulnerable' ? <ShieldAlert className="w-3.5 h-3.5" style={{ color: sm.color }} />
                : <ShieldCheck className="w-3.5 h-3.5" style={{ color: sm.color }} />}
              <span className="text-xs font-mono" style={{ color: sm.color }}>
                {state === 'vulnerable'
                  ? t('pages.digitalTwinSimulator.vulnerable_paths', { count: result.attack_paths ?? 0 })
                  : t('pages.digitalTwinSimulator.not_vulnerable')}
              </span>
            </div>
            {result.details && (
              <p className="text-[10px] font-mono text-[var(--text-muted)] leading-relaxed">{result.details}</p>
            )}
          </>
        )}
      </div>
    </motion.div>
  )
}

export default function DigitalTwinSimulator() {
  const { t } = useTranslation()
  const { clientId: routeClientId } = useParams()
  const [clients, setClients] = useState([])
  const [selectedClientId, setSelectedClientId] = useState(routeClientId ?? null)
  const { postScan } = useCommandCenterScan(selectedClientId)
  const [target, setTarget] = useState('')
  const [envProfile, setEnvProfile] = useState(null)
  const [twinProfile, setTwinProfile] = useState(null)
  const [summary, setSummary] = useState(null)
  const [rawFindings, setRawFindings] = useState([])
  const [results, setResults] = useState({})
  const [runningId, setRunningId] = useState(null)
  const [pendingJobs, setPendingJobs] = useState({})
  const [toast, setToast] = useState(null)
  const [showParams, setShowParams] = useState(false)
  const [probeDepth, setProbeDepth] = useState('standard')
  const [maxProbeUrls, setMaxProbeUrls] = useState('32')
  const [timeoutMs, setTimeoutMs] = useState('8000')
  const [probePaths, setProbePaths] = useState('')
  const [toggles, setToggles] = useState(() =>
    Object.fromEntries(TOGGLES.map((tg) => [tg.key, tg.defaultVal])),
  )
  const hubParams = useMemo(() => ({
    probe_depth: probeDepth,
    max_probe_urls: Number(maxProbeUrls) || 32,
    timeout_ms: Number(timeoutMs) || 8000,
    ...toggles,
    ...(probePaths.trim() ? { probe_paths: probePaths.trim() } : {}),
  }), [probeDepth, maxProbeUrls, timeoutMs, toggles, probePaths])
  useHubBodySync(ENGINE, () => ({
    engine: ENGINE,
    client_id: Number(selectedClientId),
    target: target.trim(),
    ...hubParams,
  }))

  const detailFindings = useMemo(() => rawFindings.filter((f) => !isSummary(f)), [rawFindings])

  const {
    filteredFindings,
    counts,
    searchQuery,
    setSearchQuery,
    severityFilter,
    setSeverityFilter,
    exportCsv,
    refreshFromHistory,
    historyLoading,
    lastUpdated,
    lastJobId,
    setLastUpdated,
    setLastJobId,
  } = useWeissmanEnginePage(ENGINE, detailFindings)

  useEffect(() => {
    refreshFromHistory().then((run) => {
      if (run?.findings?.length) {
        applyHistoryFindings(run, setRawFindings, { setLastUpdated, setJobId: setLastJobId })
        const sum = run.findings.find(isSummary)
        if (sum) {
          setSummary(sum)
          if (sum.twin_profile) setTwinProfile(sum.twin_profile)
        }
      }
    })
  }, [refreshFromHistory, setLastUpdated, setLastJobId])

  const handleRefresh = useCallback(async () => {
    const run = await refreshFromHistory()
    if (applyHistoryFindings(run, setRawFindings, { setLastUpdated, setJobId: setLastJobId })) {
      const sum = run.findings.find(isSummary)
      if (sum) {
        setSummary(sum)
        if (sum.twin_profile) setTwinProfile(sum.twin_profile)
      }
    }
  }, [refreshFromHistory, setLastUpdated, setLastJobId])

  useEffect(() => {
    apiFetch('/api/clients')
      .then((r) => (r.ok ? r.json() : []))
      .then((d) => { if (Array.isArray(d)) setClients(d) })
      .catch(() => setClients([]))
  }, [])

  useEffect(() => {
    if (!selectedClientId) { setEnvProfile(null); return }
    const client = clients.find((c) => String(c.id) === String(selectedClientId))
    if (client) {
      let domains = client.domains
      if (typeof domains === 'string') { try { domains = JSON.parse(domains) } catch { domains = [] } }
      let techStack = client.tech_stack
      if (typeof techStack === 'string') { try { techStack = JSON.parse(techStack) } catch { techStack = [] } }
      setEnvProfile({
        name: client.name,
        domains: Array.isArray(domains) ? domains : [],
        tech_stack: Array.isArray(techStack) ? techStack : [],
      })
    }
  }, [selectedClientId, clients])

  useClientTargetPrefill(selectedClientId, clients, setTarget)

  const showToast = useCallback((sev, msg) => {
    const id = Date.now()
    setToast({ id, sev, msg })
    setTimeout(() => setToast((cur) => (cur?.id === id ? null : cur)), 5000)
  }, [])

  const buildScanBody = useCallback((scenarioId) => {
    const primaryTarget = target.trim()
      || (envProfile?.domains?.[0]
        ? (envProfile.domains[0].startsWith('http') ? envProfile.domains[0] : `https://${envProfile.domains[0]}`)
        : '')
    const body = {
      engine: ENGINE,
      client_id: Number(selectedClientId),
      target: primaryTarget,
      scenario: scenarioId ?? 'profile',
      probe_depth: probeDepth,
      max_probe_urls: Number(maxProbeUrls) || 32,
      timeout_ms: Number(timeoutMs) || 8000,
      ...toggles,
    }
    if (probePaths.trim()) body.probe_paths = probePaths.trim()
    return body
  }, [target, envProfile, selectedClientId, probeDepth, maxProbeUrls, timeoutMs, toggles, probePaths])

  const applyFindings = useCallback((findings, scenarioId, job) => {
    setRawFindings(findings)
    const sum = findings.find(isSummary)
    if (sum) {
      setSummary(sum)
      if (sum.twin_profile) setTwinProfile(sum.twin_profile)
    }
    const profileFinding = findings.find((f) => f.category === 'twin_profile')
    if (profileFinding?.twin_profile) setTwinProfile(profileFinding.twin_profile)

    const paths = findings.filter((f) =>
      (f.category === 'scenario_probe' || f.category === 'attack_path')
      && (f.severity || '').toLowerCase() !== 'info'
      && (!scenarioId || f.scenario === scenarioId),
    ).length

    if (scenarioId) {
      setResults((prev) => ({
        ...prev,
        [scenarioId]: {
          vulnerable: paths > 0,
          attack_paths: paths || findings.filter((f) => f.scenario === scenarioId).length,
          details: uiJobStatus(job.status) === 'completed'
            ? t('pages.digitalTwinSimulator.simulation_signals', { count: findings.filter((f) => f.scenario === scenarioId).length })
            : t('pages.digitalTwinSimulator.simulation_status', { status: job.status }),
          pending: false,
        },
      }))
    }
  }, [t])

  const handleSimulate = useCallback(async (scenarioId) => {
    if (!selectedClientId) { showToast('error', t('pages.digitalTwinSimulator.select_client_first')); return }
    const body = buildScanBody(scenarioId)
    if (!body.target) { showToast('error', t('pages.digitalTwinSimulator.no_domain')); return }
    setRunningId(scenarioId)
    try {
      const { ok, data: d, status } = await postScan(body)
      if (!ok) { showToast('error', d.detail || t('pages.digitalTwinSimulator.simulation_failed')); return }
      const jobId = d.job_id ?? ''
      showToast('info', t('pages.digitalTwinSimulator.simulation_queued', { jobId }))
      if (jobId) setPendingJobs((prev) => ({ ...prev, [scenarioId]: jobId }))
      setResults((prev) => ({ ...prev, [scenarioId]: { pending: true, jobId } }))
    } catch (e) {
      showToast('error', e?.message ?? t('common.error'))
    } finally {
      setRunningId(null)
    }
  }, [selectedClientId, buildScanBody, showToast, t])

  const handleBuildTwin = useCallback(async () => {
    if (!selectedClientId) { showToast('error', t('pages.digitalTwinSimulator.select_client_first')); return }
    const body = buildScanBody('all')
    if (!body.target) { showToast('error', t('pages.digitalTwinSimulator.no_domain')); return }
    setRunningId('all')
    try {
      const { ok, data: d, status } = await postScan(body)
      if (!ok) { showToast('error', d.detail || t('pages.digitalTwinSimulator.simulation_failed')); return }
      const jobId = d.job_id ?? ''
      showToast('info', t('pages.digitalTwinSimulator.full_twin_queued', { jobId }))
      if (jobId) setPendingJobs((prev) => ({ ...prev, all: jobId }))
    } catch (e) {
      showToast('error', e?.message ?? t('common.error'))
    } finally {
      setRunningId(null)
    }
  }, [selectedClientId, buildScanBody, showToast, t])

  const activePoll = Object.entries(pendingJobs).find(([, jobId]) => jobId)?.[0] ?? null
  const activeJobId = activePoll ? pendingJobs[activePoll] : null

  useJobPoll(activeJobId, {
    enabled: Boolean(activeJobId && activePoll),
    onComplete: async (job) => {
      const scenarioId = activePoll === 'all' ? null : activePoll
      const findings = await resolveJobFindings(job, ENGINE, selectedClientId)
      applyFindings(findings, scenarioId, job)
      setPendingJobs((prev) => {
        const next = { ...prev }
        delete next[activePoll]
        return next
      })
    },
  })

  const handleRunAll = useCallback(async () => {
    for (const id of SIMULATION_SCENARIO_IDS) {
      await handleSimulate(id)
    }
  }, [handleSimulate])

  const clearResults = useCallback(() => {
    setResults({})
    setPendingJobs({})
    setSummary(null)
    setTwinProfile(null)
    setRawFindings([])
  }, [])

  const overview = useMemo(() => {
    const vals = Object.values(results)
    return {
      simulated: vals.filter((r) => !r.pending).length,
      vulnerable: vals.filter((r) => !r.pending && r.vulnerable).length,
      clear: vals.filter((r) => !r.pending && !r.vulnerable).length,
      running: vals.filter((r) => r.pending).length,
    }
  }, [results])
  const hasAnyResult = Object.keys(results).length > 0 || summary
  const isScanning = Object.values(pendingJobs).some(Boolean) || !!runningId

  return (
    <PageShell hideHubParams engineId={ENGINE} title={t('pages.digitalTwinSimulator.title')} badge={t('pages.digitalTwinSimulator.badge')}
      badgeColor="#8b5cf6" subtitle={t('pages.digitalTwinSimulator.subtitle')}
      actions={(
        <ShellScanActions
          onRefresh={handleRefresh}
          onExport={exportCsv}
          refreshLoading={historyLoading}
          refreshDisabled={isScanning}
          exportDisabled={!filteredFindings.length}
        />
      )}
    >
      {toast && (
        <div className={`fixed top-16 right-4 z-50 rounded-xl border px-4 py-3 text-sm font-mono max-w-sm shadow-2xl ${toast.sev === 'error' ? 'bg-rose-950/90 border-rose-500/40 text-rose-200' : 'bg-black/80 border-[#8b5cf6]/30 text-[#8b5cf6]'}`}>
          {toast.msg}
        </div>
      )}

      <div className="rounded-2xl bg-[var(--bg-2)] backdrop-blur-md border border-[var(--border-default)] p-5 mb-6">
        <div className="flex flex-wrap items-end gap-4">
          <div className="flex flex-col gap-1">
            <label className="text-[10px] font-mono uppercase tracking-wider text-[var(--text-muted)]">{t('pages.digitalTwinSimulator.client_label')}</label>
            <select value={selectedClientId ?? ''} onChange={(e) => setSelectedClientId(e.target.value || null)}
              className="bg-[var(--scrim)] border border-[var(--border-default)] rounded-lg px-3 py-2 text-xs text-[var(--text-secondary)] font-mono focus:outline-none focus:border-[#8b5cf6]/40 min-w-[180px]">
              <option value="">{t('pages.digitalTwinSimulator.select_client')}</option>
              {clients.map((c) => <option key={c.id} value={c.id}>{c.name}</option>)}
            </select>
          </div>
          <div className="flex flex-col gap-1 flex-1 min-w-[220px]">
            <label className="text-[10px] font-mono uppercase tracking-wider text-[var(--text-muted)]">{t('pages.digitalTwinSimulator.target_label')}</label>
            <input type="text" value={target} onChange={(e) => setTarget(e.target.value)} placeholder="https://example.com"
              className="bg-[var(--scrim)] border border-[var(--border-default)] rounded-lg px-3 py-2 text-xs text-[var(--text-secondary)] font-mono focus:outline-none focus:border-[#8b5cf6]/40" />
          </div>
          <button type="button" onClick={handleBuildTwin} disabled={!selectedClientId || !!runningId}
            className="px-4 py-2 rounded-xl font-mono text-sm border border-violet-500/40 text-violet-300 bg-violet-500/10 hover:bg-violet-500/20 disabled:opacity-40 transition-all">
            {t('pages.digitalTwinSimulator.build_full_twin')}
          </button>
          <button type="button" onClick={() => setShowParams((s) => !s)}
            className="px-3 py-2 rounded-xl font-mono text-xs border border-[var(--border-default)] text-[var(--text-tertiary)] hover:text-[var(--text-secondary)] transition-all">
            {showParams ? t('pages.digitalTwinSimulator.hide_params') : t('pages.digitalTwinSimulator.show_params')}
          </button>
        </div>

        <AnimatePresence initial={false}>
          {showParams && (
            <motion.div initial={{ height: 0, opacity: 0 }} animate={{ height: 'auto', opacity: 1 }} exit={{ height: 0, opacity: 0 }} className="overflow-hidden">
              <div className="mt-5 pt-5 border-t border-[var(--border-subtle)] grid grid-cols-1 lg:grid-cols-3 gap-6">
                <div>
                  <div className="text-[10px] font-mono uppercase tracking-wider text-[var(--text-muted)] mb-2">{t('pages.digitalTwinSimulator.probe_categories')}</div>
                  <div className="grid grid-cols-1 gap-1.5">
                    {TOGGLES.map((tg) => (
                      <label key={tg.key} className="flex items-center gap-2 text-xs font-mono text-[var(--text-secondary)] cursor-pointer">
                        <input type="checkbox" checked={!!toggles[tg.key]}
                          onChange={(e) => setToggles((p) => ({ ...p, [tg.key]: e.target.checked }))} className="accent-violet-500" />
                        {t(`pages.digitalTwinSimulator.${tg.labelKey}`)}
                      </label>
                    ))}
                  </div>
                </div>
                <div className="space-y-4">
                  <div>
                    <label className="text-[10px] font-mono uppercase tracking-wider text-[var(--text-muted)] block mb-1">{t('pages.digitalTwinSimulator.probe_depth_label')}</label>
                    <select value={probeDepth} onChange={(e) => setProbeDepth(e.target.value)}
                      className="w-full bg-[var(--scrim)] border border-[var(--border-default)] rounded-lg px-3 py-1.5 text-[11px] text-[var(--text-secondary)] font-mono">
                      {['quick', 'standard', 'deep'].map((o) => (
                        <option key={o} value={o}>{t(`pages.digitalTwinSimulator.depth_${o}`)}</option>
                      ))}
                    </select>
                  </div>
                  <div>
                    <label className="text-[10px] font-mono uppercase tracking-wider text-[var(--text-muted)] block mb-1">{t('pages.digitalTwinSimulator.extra_paths_label')}</label>
                    <input type="text" value={probePaths} onChange={(e) => setProbePaths(e.target.value)} placeholder="/api,/search"
                      className="w-full bg-[var(--scrim)] border border-[var(--border-default)] rounded-lg px-3 py-1.5 text-[11px] text-[var(--text-secondary)] font-mono" />
                  </div>
                </div>
                <div className="space-y-4">
                  <div className="grid grid-cols-2 gap-3">
                    <div>
                      <label className="text-[10px] font-mono uppercase tracking-wider text-[var(--text-muted)] block mb-1">{t('pages.digitalTwinSimulator.max_urls_label')}</label>
                      <input type="number" min={4} max={64} value={maxProbeUrls} onChange={(e) => setMaxProbeUrls(e.target.value)}
                        className="w-full bg-[var(--scrim)] border border-[var(--border-default)] rounded-lg px-3 py-1.5 text-[11px] text-[var(--text-secondary)] font-mono" />
                    </div>
                    <div>
                      <label className="text-[10px] font-mono uppercase tracking-wider text-[var(--text-muted)] block mb-1">{t('pages.digitalTwinSimulator.timeout_label')}</label>
                      <input type="number" min={2000} max={30000} step={500} value={timeoutMs} onChange={(e) => setTimeoutMs(e.target.value)}
                        className="w-full bg-[var(--scrim)] border border-[var(--border-default)] rounded-lg px-3 py-1.5 text-[11px] text-[var(--text-secondary)] font-mono" />
                    </div>
                  </div>
                </div>
              </div>
            </motion.div>
          )}
        </AnimatePresence>
      </div>

      {summary && <Scorecard summary={summary} t={t} />}

      <div className="flex flex-wrap items-center justify-end gap-2 mb-8">
        {hasAnyResult && (
          <button type="button" onClick={clearResults}
            className="inline-flex items-center gap-1.5 px-3 py-2 rounded-xl font-mono text-xs border border-[var(--border-default)] text-[var(--text-tertiary)] hover:text-[var(--text-primary)] transition-all">
            <Trash2 className="w-3.5 h-3.5" />
            {t('pages.digitalTwinSimulator.clear_results')}
          </button>
        )}
        <button type="button" onClick={handleRunAll} disabled={!selectedClientId || !!runningId}
          className="px-4 py-2 rounded-xl font-mono text-sm border border-[#8b5cf6]/40 text-[#8b5cf6] bg-[#8b5cf6]/10 hover:bg-[#8b5cf6]/20 disabled:opacity-40 transition-all">
          {t('pages.digitalTwinSimulator.run_all')}
        </button>
      </div>

      {hasAnyResult && (
        <div className="grid grid-cols-2 sm:grid-cols-4 gap-3 mb-8">
          {[
            { key: 'overview_simulated', value: overview.simulated, color: '#a78bfa' },
            { key: 'overview_vulnerable', value: overview.vulnerable, color: '#f43f5e' },
            { key: 'overview_clear', value: overview.clear, color: '#34d399' },
            { key: 'overview_running', value: overview.running, color: '#38bdf8' },
          ].map((s) => (
            <div key={s.key} className="rounded-2xl bg-[var(--bg-2)] border border-[var(--border-default)] p-4">
              <div className="text-[10px] font-mono uppercase tracking-widest text-[var(--text-muted)]">{t(`pages.digitalTwinSimulator.${s.key}`)}</div>
              <div className="text-2xl font-bold mt-1 tabular-nums" style={{ color: s.color }}>{s.value}</div>
            </div>
          ))}
        </div>
      )}

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-8">
        <div className="space-y-4">
          <h3 className="text-xs font-mono text-[var(--text-tertiary)] uppercase tracking-widest">{t('pages.digitalTwinSimulator.env_profile')}</h3>
          <div className="rounded-2xl bg-[var(--bg-2)] backdrop-blur-md border border-[var(--border-default)] p-5 space-y-4">
            {envProfile && (
              <>
                <div>
                  <p className="text-[10px] font-mono text-[var(--text-muted)] uppercase tracking-widest mb-1">{t('pages.digitalTwinSimulator.client_heading')}</p>
                  <p className="text-sm font-semibold text-white">{envProfile.name}</p>
                </div>
                {envProfile.domains.length > 0 && (
                  <div>
                    <p className="text-[10px] font-mono text-[var(--text-muted)] uppercase tracking-widest mb-2">{t('pages.digitalTwinSimulator.domains_heading')}</p>
                    <div className="space-y-1">
                      {envProfile.domains.map((d, i) => (
                        <p key={i} className="text-[11px] font-mono text-cyan-300/80 truncate">{d}</p>
                      ))}
                    </div>
                  </div>
                )}
              </>
            )}
            <TwinProfilePanel profile={twinProfile} t={t} />
          </div>
        </div>

        <div className="lg:col-span-2 space-y-4">
          <h3 className="text-xs font-mono text-[var(--text-tertiary)] uppercase tracking-widest">{t('pages.digitalTwinSimulator.attack_simulations')}</h3>
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            {SIMULATION_SCENARIO_IDS.map((scenarioId) => (
              <ScenarioCard key={scenarioId} scenarioId={scenarioId} result={results[scenarioId] ?? null}
                onRun={handleSimulate} running={runningId === scenarioId} disabled={!selectedClientId} t={t} />
            ))}
          </div>
        </div>
      </div>

      <WeissmanFindingsPanel
        findings={detailFindings}
        filteredFindings={filteredFindings}
        counts={counts}
        total={detailFindings.length}
        searchQuery={searchQuery}
        onSearchChange={setSearchQuery}
        severityFilter={severityFilter}
        onSeverityChange={setSeverityFilter}
        pending={isScanning && detailFindings.length === 0}
        loading={historyLoading && detailFindings.length === 0}
        lastUpdated={lastUpdated}
        jobId={lastJobId}
        accent="#8b5cf6"
        showEmptyReady={!isScanning && detailFindings.length === 0}
        emptyReadyTitle={t('pages.digitalTwinSimulator.not_run_hint')}
        emptyReadyBody={t('pages.digitalTwinSimulator.subtitle')}
        className="mt-8"
      />
    </PageShell>
  )
}
