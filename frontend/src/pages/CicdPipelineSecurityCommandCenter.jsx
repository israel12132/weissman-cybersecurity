import { useCommandCenterScan } from '../hooks/useCommandCenterScan'
import { useSyncHubScanParams } from '../hooks/useLaunchEngineScan'
import React, { useState, useEffect, useRef, useCallback, useMemo } from 'react'
import { Link } from 'react-router-dom'
import { motion, AnimatePresence } from 'framer-motion'
import { useTranslation } from 'react-i18next'
import PageShell from './PageShell'
import ShellScanActions from '../components/engine/ShellScanActions'
import WeissmanFindingsPanel from '../components/engine/WeissmanFindingsPanel'
import { useWeissmanEnginePage, applyHistoryFindings } from '../hooks/useWeissmanEnginePage'
import { apiFetch } from '../lib/apiBase'
import { openSseStream } from '../lib/sseStream'
import { ENGINES_BY_ID } from '../lib/enginesRegistry'

const ENGINE_ID = 'cicd_pipeline'

const PLATFORMS = [
  { id: 'jenkins', label: 'Jenkins', icon: '🔧' },
  { id: 'gitlab', label: 'GitLab CI', icon: '🦊' },
  { id: 'argocd', label: 'ArgoCD', icon: '🚀' },
  { id: 'tekton', label: 'Tekton', icon: '⚙️' },
  { id: 'azure_devops', label: 'Azure DevOps', icon: '🔷' },
  { id: 'github_actions', label: 'GitHub Actions', icon: '🐙' },
  { id: 'drone', label: 'Drone CI', icon: '🛸' },
  { id: 'circleci', label: 'CircleCI', icon: '⭕' },
  { id: 'spinnaker', label: 'Spinnaker', icon: '🌀' },
  { id: 'teamcity', label: 'TeamCity', icon: '🏗️' },
  { id: 'buildkite', label: 'Buildkite', icon: '🐝' },
  { id: 'harness', label: 'Harness', icon: '🎯' },
  { id: 'woodpecker', label: 'Woodpecker', icon: '🪶' },
  { id: 'bitbucket', label: 'Bitbucket Pipelines', icon: '🪣' },
]

const FRAMEWORKS = ['NIST-SA-12', 'SOC2-CC8.1', 'PCI-DSS-6.3.2', 'MITRE-T1195.002', 'CIS-DevSecOps', 'ISO-27001-A.8']
const SEVERITIES = ['info', 'low', 'medium', 'high', 'critical']
const INTENSITIES = ['light', 'normal', 'aggressive']

const SEV_COLOR = {
  critical: '#ef4444',
  high: '#f97316',
  medium: '#f59e0b',
  low: '#22d3ee',
  info: '#64748b',
}

const DEFAULT_PARAMS = {
  intensity: 'normal',
  probe_fingerprint: true,
  probe_api: true,
  probe_config: true,
  probe_repo: true,
  probe_workflow_analysis: true,
  probe_runner_tokens: true,
  probe_jenkins_console: true,
  probe_build_logs: true,
  probe_artifact_exposure: true,
  probe_repo_governance: true,
  probe_secret_scan: true,
  attack_path_synthesis: true,
  posture_scoring: true,
  repo_url: '',
  repo_ref: '',
  github_token: '',
  gitlab_token: '',
  azure_devops_pat: '',
  bearer_token: '',
  auth_header: '',
  platform_filter: PLATFORMS.map((p) => p.id),
  compliance_frameworks: [...FRAMEWORKS],
  api_paths: '',
  config_paths: '',
  min_severity: 'info',
  max_requests: '600',
  max_repo_files: '32',
  timeout_ms: '10000',
  max_concurrency: '16',
  dry_run: false,
}

const splitLines = (s) => String(s || '').split('\n').map((x) => x.trim()).filter(Boolean)
const numOr = (v, d) => {
  const n = Number(v)
  return Number.isFinite(n) ? n : d
}

function buildScanBody(params, clientId, target) {
  const body = {
    engine: ENGINE_ID,
    client_id: Number(clientId),
    target: (target || '').trim(),
    timeout: 300,
    intensity: params.intensity,
    probe_fingerprint: !!params.probe_fingerprint,
    probe_api: !!params.probe_api,
    probe_config: !!params.probe_config,
    probe_repo: !!params.probe_repo,
    probe_workflow_analysis: !!params.probe_workflow_analysis,
    probe_runner_tokens: !!params.probe_runner_tokens,
    probe_jenkins_console: !!params.probe_jenkins_console,
    probe_build_logs: !!params.probe_build_logs,
    probe_artifact_exposure: !!params.probe_artifact_exposure,
    probe_repo_governance: !!params.probe_repo_governance,
    probe_secret_scan: !!params.probe_secret_scan,
    attack_path_synthesis: !!params.attack_path_synthesis,
    posture_scoring: !!params.posture_scoring,
    min_severity: params.min_severity,
    max_requests: numOr(params.max_requests, 600),
    max_repo_files: numOr(params.max_repo_files, 32),
    timeout_ms: numOr(params.timeout_ms, 10000),
    max_concurrency: numOr(params.max_concurrency, 16),
    dry_run: !!params.dry_run,
  }
  if (params.repo_url.trim()) body.repo_url = params.repo_url.trim()
  if (params.repo_ref.trim()) body.repo_ref = params.repo_ref.trim()
  if (params.github_token.trim()) body.github_token = params.github_token.trim()
  if (params.gitlab_token.trim()) body.gitlab_token = params.gitlab_token.trim()
  if (params.azure_devops_pat.trim()) body.azure_devops_pat = params.azure_devops_pat.trim()
  if (params.bearer_token.trim()) body.bearer_token = params.bearer_token.trim()
  if (params.auth_header.trim()) body.auth_header = params.auth_header.trim()
  if (params.platform_filter.length && params.platform_filter.length < PLATFORMS.length) {
    body.platform_filter = params.platform_filter
  }
  if (params.compliance_frameworks.length && params.compliance_frameworks.length < FRAMEWORKS.length) {
    body.compliance_frameworks = params.compliance_frameworks
  }
  const apiPaths = splitLines(params.api_paths)
  if (apiPaths.length) body.api_paths = apiPaths
  const configPaths = splitLines(params.config_paths)
  if (configPaths.length) body.config_paths = configPaths
  return body
}

function Section({ title, icon, accent = '#84cc16', count, defaultOpen = true, children }) {
  const [open, setOpen] = useState(defaultOpen)
  return (
    <div className="rounded-xl border bg-[var(--table-surface)] overflow-hidden" style={{ borderColor: `${accent}22` }}>
      <button type="button" onClick={() => setOpen((o) => !o)} className="w-full flex items-center justify-between px-3 py-2.5 hover:bg-[var(--row-hover-bg)] transition-colors">
        <span className="flex items-center gap-2 text-[11px] font-mono uppercase tracking-[0.18em] font-semibold" style={{ color: accent }}>
          <span>{icon}</span>
          {title}
          {count != null && <span className="text-[var(--text-disabled)] normal-case tracking-normal">· {count}</span>}
        </span>
        <span className={`text-[var(--text-muted)] text-xs transition-transform ${open ? 'rotate-90' : ''}`}>▶</span>
      </button>
      {open && <div className="px-3 pb-3 pt-1 space-y-3 border-t border-[var(--border-subtle)]">{children}</div>}
    </div>
  )
}

function Hint({ children }) {
  if (!children) return null
  return <span className="block text-[9px] font-mono text-[var(--text-disabled)] mt-0.5 leading-snug">{children}</span>
}

function Num({ label, value, onChange, min, max, hint }) {
  return (
    <label className="block space-y-1">
      <span className="text-[10px] font-mono text-[var(--text-muted)] uppercase tracking-wide">{label}</span>
      <input type="number" min={min} max={max} value={value} onChange={(e) => onChange(e.target.value)}
        className="w-full rounded-lg bg-[var(--bg-3)] border border-[var(--border-default)] px-3 py-1.5 text-sm text-white font-mono focus:outline-none focus:border-lime-400/40" />
      <Hint>{hint}</Hint>
    </label>
  )
}

function Sel({ label, value, onChange, options, hint }) {
  return (
    <label className="block space-y-1">
      <span className="text-[10px] font-mono text-[var(--text-muted)] uppercase tracking-wide">{label}</span>
      <select value={value} onChange={(e) => onChange(e.target.value)}
        className="w-full rounded-lg bg-[var(--bg-3)] border border-[var(--border-default)] px-3 py-1.5 text-sm text-white focus:outline-none focus:border-lime-400/40">
        {options.map((o) => <option key={o} value={o}>{o}</option>)}
      </select>
      <Hint>{hint}</Hint>
    </label>
  )
}

function Txt({ label, value, onChange, placeholder, hint, type = 'text' }) {
  return (
    <label className="block space-y-1">
      <span className="text-[10px] font-mono text-[var(--text-muted)] uppercase tracking-wide">{label}</span>
      <input type={type} value={value} onChange={(e) => onChange(e.target.value)} placeholder={placeholder}
        className="w-full rounded-lg bg-[var(--bg-3)] border border-[var(--border-default)] px-3 py-1.5 text-sm text-white font-mono placeholder-white/20 focus:outline-none focus:border-lime-400/40" />
      <Hint>{hint}</Hint>
    </label>
  )
}

function Area({ label, value, onChange, placeholder, rows = 3, hint }) {
  return (
    <label className="block space-y-1">
      <span className="text-[10px] font-mono text-[var(--text-muted)] uppercase tracking-wide">{label}</span>
      <textarea rows={rows} value={value} onChange={(e) => onChange(e.target.value)} placeholder={placeholder}
        className="w-full rounded-lg bg-[var(--bg-3)] border border-[var(--border-default)] px-3 py-1.5 text-xs text-white font-mono placeholder-white/20 focus:outline-none focus:border-lime-400/40 resize-y" />
      <Hint>{hint}</Hint>
    </label>
  )
}

function Toggle({ label, value, onChange, hint }) {
  return (
    <div className="flex items-start justify-between gap-3 py-0.5">
      <div className="min-w-0">
        <span className="text-[11px] font-mono text-[var(--text-secondary)]">{label}</span>
        <Hint>{hint}</Hint>
      </div>
      <button type="button" role="switch" aria-checked={value} onClick={() => onChange(!value)}
        className={`relative shrink-0 mt-0.5 w-9 h-5 rounded-full transition-all ${value ? 'bg-lime-500/40' : 'bg-[var(--scrim)] border border-[var(--border-default)]'}`}>
        <span className={`absolute top-0.5 w-4 h-4 rounded-full bg-white shadow transition-all ${value ? 'left-[18px]' : 'left-0.5'}`} />
      </button>
    </div>
  )
}

function SupplyChainGraphCanvas({ graph, running }) {
  const canvasRef = useRef(null)
  const animRef = useRef(null)

  useEffect(() => {
    const canvas = canvasRef.current
    if (!canvas) return undefined
    const ctx = canvas.getContext('2d')
    const dpr = window.devicePixelRatio || 1
    const w = canvas.offsetWidth
    const h = canvas.offsetHeight
    canvas.width = w * dpr
    canvas.height = h * dpr
    ctx.scale(dpr, dpr)

    const nodes = Array.isArray(graph?.nodes) ? graph.nodes : []
    const edges = Array.isArray(graph?.edges) ? graph.edges : []

    const layout = nodes.map((n, i) => {
      const ang = (i / Math.max(nodes.length, 1)) * Math.PI * 2 - Math.PI / 2
      const r = n.type === 'target' ? 0 : Math.min(w, h) * 0.32
      const cx = w / 2
      const cy = h / 2
      const sensitive = ['rce', 'credential', 'persistence', 'exposure'].includes(n.type)
      return {
        ...n,
        x: cx + Math.cos(ang) * r,
        y: cy + Math.sin(ang) * r,
        sensitive,
        pulse: Math.random() * Math.PI * 2,
        size: n.type === 'target' ? 18 : sensitive ? 12 : 8,
      }
    })

    const colorFor = (type) => {
      if (type === 'target') return '#84cc16'
      if (type === 'rce') return '#ef4444'
      if (type === 'credential') return '#f97316'
      if (type === 'persistence') return '#a855f7'
      if (type === 'exposure') return '#f59e0b'
      if (type === 'platform') return '#22d3ee'
      return '#94a3b8'
    }

    const draw = () => {
      ctx.clearRect(0, 0, w, h)
      edges.forEach((e) => {
        const a = layout.find((n) => n.id === e.from)
        const b = layout.find((n) => n.id === e.to)
        if (!a || !b) return
        ctx.beginPath()
        ctx.moveTo(a.x, a.y)
        ctx.lineTo(b.x, b.y)
        ctx.strokeStyle = 'rgba(132,204,22,0.18)'
        ctx.lineWidth = 1
        ctx.stroke()
      })
      layout.forEach((n) => {
        n.pulse += running ? 0.06 : 0.02
        const glow = 0.5 + Math.sin(n.pulse) * 0.5
        const col = colorFor(n.type)
        ctx.beginPath()
        ctx.arc(n.x, n.y, n.size * (running ? 1 + glow * 0.2 : 1), 0, Math.PI * 2)
        ctx.fillStyle = col + (n.sensitive ? 'cc' : '99')
        ctx.fill()
        if (n.label) {
          ctx.font = '8px monospace'
          ctx.fillStyle = 'rgba(255,255,255,0.55)'
          ctx.textAlign = 'center'
          ctx.fillText(String(n.label).slice(0, 16), n.x, n.y + n.size + 10)
        }
      })
      animRef.current = requestAnimationFrame(draw)
    }
    draw()
    return () => { if (animRef.current) cancelAnimationFrame(animRef.current) }
  }, [graph, running])

  return (
    <canvas ref={canvasRef} className="w-full h-full rounded-xl"
      style={{ background: 'radial-gradient(ellipse at center, rgba(77,124,15,0.2) 0%, rgba(0,0,0,0.65) 70%)' }} />
  )
}

function PostureGauge({ score, grade }) {
  const pct = Math.min(100, Math.max(0, score ?? 0))
  const color = pct >= 70 ? '#ef4444' : pct >= 40 ? '#f59e0b' : '#84cc16'
  return (
    <div className="relative w-36 h-36 mx-auto">
      <svg viewBox="0 0 100 100" className="w-full h-full -rotate-90">
        <circle cx="50" cy="50" r="42" fill="none" stroke="rgba(255,255,255,0.06)" strokeWidth="8" />
        <circle cx="50" cy="50" r="42" fill="none" stroke={color} strokeWidth="8"
          strokeDasharray={`${pct * 2.64} 264`} strokeLinecap="round" style={{ filter: `drop-shadow(0 0 8px ${color}80)` }} />
      </svg>
      <div className="absolute inset-0 flex flex-col items-center justify-center">
        <span className="text-3xl font-bold text-white">{pct || '—'}</span>
        {grade && <span className="text-lg font-mono text-lime-300/80">{grade}</span>}
        <span className="text-[9px] font-mono text-[var(--text-muted)] uppercase tracking-widest">Exposure</span>
      </div>
    </div>
  )
}

function MetricTile({ label, value, accent = '#84cc16' }) {
  return (
    <div className="rounded-xl border border-[var(--border-default)] bg-[var(--bg-2)] backdrop-blur-md p-4" style={{ boxShadow: `inset 0 1px 0 ${accent}20` }}>
      <p className="text-[9px] font-mono uppercase tracking-[0.2em] text-[var(--text-muted)] mb-1">{label}</p>
      <p className="text-2xl font-bold text-white">{value ?? '—'}</p>
    </div>
  )
}

const sevColor = (s) => {
  const c = SEV_COLOR[(s || 'info').toLowerCase()] || SEV_COLOR.info
  return { color: c }
}

function RiskDimensionBar({ label, value, accent = '#84cc16' }) {
  const pct = Math.min(100, Math.max(0, value ?? 0))
  return (
    <div className="space-y-1">
      <div className="flex justify-between text-[9px] font-mono uppercase tracking-wide">
        <span className="text-[var(--text-muted)]">{label}</span>
        <span style={{ color: accent }}>{pct}%</span>
      </div>
      <div className="h-1.5 rounded-full bg-[var(--row-hover-bg)] overflow-hidden">
        <div className="h-full rounded-full transition-all duration-700" style={{ width: `${pct}%`, background: accent, boxShadow: `0 0 8px ${accent}60` }} />
      </div>
    </div>
  )
}

function PolicyHitsPanel({ policyHits }) {
  if (!policyHits || typeof policyHits !== 'object') return null
  const entries = Object.entries(policyHits).sort((a, b) => b[1] - a[1]).slice(0, 12)
  if (!entries.length) return null
  return (
    <div className="rounded-xl border border-[var(--border-default)] bg-[var(--bg-2)] p-3 space-y-2">
      <p className="text-[9px] font-mono uppercase tracking-[0.2em] text-[var(--text-muted)]">WZ Policy Catalog Hits</p>
      <div className="flex flex-wrap gap-1.5">
        {entries.map(([id, count]) => (
          <span key={id} className="text-[9px] font-mono px-2 py-0.5 rounded border border-lime-500/25 text-lime-200/90 bg-lime-500/10">
            {id} ×{count}
          </span>
        ))}
      </div>
    </div>
  )
}

function CompliancePosturePanel({ compliancePosture }) {
  if (!compliancePosture || typeof compliancePosture !== 'object') return null
  const entries = Object.entries(compliancePosture)
  if (!entries.length) return null
  return (
    <div className="rounded-xl border border-cyan-500/20 bg-cyan-950/10 p-3 space-y-2">
      <p className="text-[9px] font-mono uppercase tracking-[0.2em] text-cyan-300/60">Compliance Posture</p>
      <div className="grid grid-cols-2 gap-2">
        {entries.map(([fw, data]) => (
          <div key={fw} className="rounded-lg border border-[var(--border-default)] bg-[var(--bg-2)] px-2 py-1.5">
            <p className="text-[9px] font-mono text-[var(--text-muted)] truncate">{fw}</p>
            <p className="text-lg font-bold text-cyan-200">{data?.score ?? '—'}</p>
            <p className="text-[8px] font-mono text-[var(--text-disabled)]">{data?.policy_violations ?? 0} policy hits</p>
          </div>
        ))}
      </div>
    </div>
  )
}

function RemediationPlaybookPanel({ playbook }) {
  const actions = playbook?.actions
  if (!Array.isArray(actions) || !actions.length) return null
  return (
    <div className="rounded-xl border border-amber-500/20 bg-amber-950/10 p-3 space-y-2">
      <p className="text-[9px] font-mono uppercase tracking-[0.2em] text-amber-300/70">
        Remediation Playbook · {playbook.total ?? actions.length} actions
      </p>
      <div className="space-y-1.5 max-h-48 overflow-auto">
        {actions.map((a, i) => (
          <div key={i} className="flex gap-2 text-[10px] border-b border-[var(--border-subtle)] pb-1.5 last:border-0">
            <span className="shrink-0 font-mono text-amber-400/90">{a.priority || 'P?'}</span>
            <span className="text-[var(--text-tertiary)] leading-snug">{a.action}</span>
          </div>
        ))}
      </div>
    </div>
  )
}

export default function CicdPipelineSecurityCommandCenter() {
  const { t } = useTranslation()
  const engine = ENGINES_BY_ID[ENGINE_ID]
  const [clients, setClients] = useState([])
  const [selectedClientId, setSelectedClientId] = useState('')
  const { postScan } = useCommandCenterScan(selectedClientId)
  const [target, setTarget] = useState('')
  const [params, setParams] = useState(DEFAULT_PARAMS)
  useSyncHubScanParams(ENGINE_ID, params)
  const [running, setRunning] = useState(false)
  const [lines, setLines] = useState([])
  const [metrics, setMetrics] = useState(null)
  const [findings, setFindings] = useState([])
  const [showPreview, setShowPreview] = useState(false)
  const esRef = useRef(null)

  const setField = useCallback((key, val) => setParams((p) => ({ ...p, [key]: val })), [])
  const togglePlatform = useCallback((id) => {
    setParams((p) => {
      const has = p.platform_filter.includes(id)
      const next = has ? p.platform_filter.filter((x) => x !== id) : [...p.platform_filter, id]
      return { ...p, platform_filter: next.length ? next : PLATFORMS.map((x) => x.id) }
    })
  }, [])
  const toggleFramework = useCallback((id) => {
    setParams((p) => {
      const has = p.compliance_frameworks.includes(id)
      const next = has ? p.compliance_frameworks.filter((x) => x !== id) : [...p.compliance_frameworks, id]
      return { ...p, compliance_frameworks: next.length ? next : [...FRAMEWORKS] }
    })
  }, [])
  const resetParams = useCallback(() => setParams({ ...DEFAULT_PARAMS }), [])

  const previewBody = useMemo(() => buildScanBody(params, selectedClientId || 0, target), [params, selectedClientId, target])
  const paramCount = useMemo(() => Object.keys(previewBody).length, [previewBody])
  const attackPaths = useMemo(() => findings.filter((f) => f.category === 'attack_path'), [findings])
  const realFindings = useMemo(
    () => findings.filter((f) => f.category !== 'attack_path' && f.category !== 'cicd_metrics'),
    [findings],
  )

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
  } = useWeissmanEnginePage(ENGINE_ID, realFindings)

  useEffect(() => {
    refreshFromHistory().then((run) => {
      if (run?.findings?.length) {
        applyHistoryFindings(run, setFindings, { setLastUpdated, setJobId: setLastJobId })
        const meta = run.findings.find((x) => x.cicd_metrics)?.cicd_metrics
        if (meta) setMetrics(meta)
      }
    })
  }, [refreshFromHistory, setLastUpdated, setLastJobId])

  const handleRefresh = useCallback(async () => {
    const run = await refreshFromHistory()
    if (applyHistoryFindings(run, setFindings, { setLastUpdated, setJobId: setLastJobId })) {
      const meta = run.findings.find((x) => x.cicd_metrics)?.cicd_metrics
      if (meta) setMetrics(meta)
    }
  }, [refreshFromHistory, setLastUpdated, setLastJobId])

  const appendLine = useCallback((msg) => setLines((prev) => [...prev.slice(-400), msg]), [])

  useEffect(() => {
    apiFetch('/api/clients').then((r) => (r.ok ? r.json() : [])).then((d) => { if (Array.isArray(d)) setClients(d) }).catch(() => {})
  }, [])

  useEffect(() => {
    if (!selectedClientId) return
    const client = clients.find((c) => String(c.id) === String(selectedClientId))
    if (!client) return
    let domains = client.domains
    if (typeof domains === 'string') { try { domains = JSON.parse(domains) } catch { domains = [] } }
    const first = Array.isArray(domains) ? (domains[0] || '') : ''
    if (first) setTarget(first.startsWith('http') ? first : `https://${first}`)
  }, [selectedClientId, clients])

  useEffect(() => () => { if (esRef.current) esRef.current.close() }, [])

  const handleRun = useCallback(async (opts = {}) => {
    const dryRun = !!opts.dryRun || !!params.dry_run
    if (!selectedClientId || !target.trim()) return
    setRunning(true)
    setLines([])
    setMetrics(null)
    setFindings([])
    appendLine(`[CI/CD] ${dryRun ? 'Planning dry-run' : 'Launching DevSecOps assessment'} — ${paramCount} params…`)

    const body = buildScanBody(params, selectedClientId, target)
    if (opts.dryRun) body.dry_run = true

    try {
      const { ok, data } = await postScan(body)
      if (!ok) {
        appendLine(`[ERROR] ${data.detail || 'Scan failed'}`)
        setRunning(false)
        return
      }
      const jobId = data.job_id
      appendLine(`[CI/CD] Job queued: ${jobId}`)
      if (esRef.current) esRef.current.close()
      const es = openSseStream(`/api/telemetry/stream?job_id=${jobId}`)
      esRef.current = es
      es.onmessage = (ev) => {
        try {
          const p = JSON.parse(ev.data)
          if (p.message) appendLine(p.message)
          if (p.status === 'completed' || p.status === 'failed') {
            es.close()
            setRunning(false)
            apiFetch(`/api/jobs/${jobId}`)
              .then((jr) => (jr.ok ? jr.json() : null))
              .then((job) => {
                const res = job?.result_json || job?.result
                const f = res?.findings || []
                setFindings(f)
                setLastUpdated(new Date().toISOString())
                if (jobId) setLastJobId(jobId)
                const meta = f.find((x) => x.cicd_metrics)?.cicd_metrics
                if (meta) setMetrics(meta)
                appendLine(`[CI/CD] ${dryRun ? 'Dry-run complete' : 'Assessment complete'} — ${f.length} findings`)
              })
              .catch(() => {})
          }
        } catch { /* ignore */ }
      }
      es.onerror = () => { es.close(); setRunning(false) }
    } catch (e) {
      appendLine(`[ERROR] ${e.message}`)
      setRunning(false)
    }
  }, [selectedClientId, target, params, paramCount, appendLine, setLastUpdated, setLastJobId])

  return (
    <PageShell
      hideHubParams
      title={t('cicdSec.title', 'CI/CD Pipeline Security Command Center')}
      subtitle={t('cicdSec.subtitle', 'Agentless DevSecOps at Wiz / Prisma / GitHub Advanced Security depth — multi-platform CI fingerprinting, workflow static analysis, secret leakage & attack-path synthesis')}
      badge="DevSecOps"
      badgeColor="#84cc16"
      icon="⛓"
      actions={(
        <ShellScanActions
          onRefresh={handleRefresh}
          onExport={exportCsv}
          refreshLoading={historyLoading}
          refreshDisabled={running}
          exportDisabled={!filteredFindings.length}
        />
      )}
    >
      <div className="space-y-6">
        <motion.div initial={{ opacity: 0, y: 12 }} animate={{ opacity: 1, y: 0 }}
          className="relative overflow-hidden rounded-2xl border border-lime-500/30 bg-gradient-to-br from-lime-950/40 via-black/60 to-emerald-950/30 p-6">
          <div className="absolute inset-0 opacity-30"
            style={{ background: 'radial-gradient(circle at 20% 50%, rgba(132,204,22,0.35), transparent 50%), radial-gradient(circle at 80% 50%, rgba(16,185,129,0.2), transparent 50%)' }} />
          <div className="relative flex flex-wrap items-center justify-between gap-4">
            <div>
              <div className="flex items-center gap-2 mb-2 flex-wrap">
                <span className="text-[10px] font-mono px-2 py-0.5 rounded-full border border-lime-400/40 text-lime-300 bg-lime-500/10 uppercase tracking-widest">
                  DevSecOps · Supply Chain
                </span>
                <span className="text-[10px] font-mono px-2 py-0.5 rounded-full border border-emerald-400/30 text-emerald-300 bg-emerald-500/10 uppercase tracking-widest">
                  {paramCount} {t('cicdSec.params_badge', 'live parameters')}
                </span>
                <span className="text-[10px] font-mono text-[var(--text-disabled)]">MITRE T1195.002 · NIST SA-12</span>
              </div>
              <h1 className="text-2xl font-bold text-white tracking-tight">{engine?.label || 'CI/CD Pipeline Security'}</h1>
              <p className="text-sm text-[var(--text-tertiary)] mt-1 max-w-2xl leading-relaxed">
                {t('cicdSec.hero_desc', 'Evidence-only: every finding requires a live HTTP/API signal or fetched pipeline artifact. No fabricated results.')}
              </p>
            </div>
            <div className="flex gap-2 flex-wrap">
              <Link to="/supply-chain" className="text-[11px] font-mono px-3 py-1.5 rounded-lg border border-[var(--border-strong)] text-[var(--text-tertiary)] hover:text-white hover:border-[var(--border-strong)] transition-colors">
                Supply Chain Hub →
              </Link>
              <Link to={`/engines/${ENGINE_ID}`} className="text-[11px] font-mono px-3 py-1.5 rounded-lg border border-[var(--border-strong)] text-[var(--text-tertiary)] hover:text-white hover:border-[var(--border-strong)] transition-colors">
                Engine Detail →
              </Link>
            </div>
          </div>
        </motion.div>

        <div className="grid grid-cols-1 xl:grid-cols-[400px_1fr] gap-6 items-start">
          <div className="xl:sticky xl:top-4 space-y-3 xl:max-h-[calc(100dvh-2rem)] xl:overflow-y-auto pr-1">
            <div className="rounded-2xl border border-lime-500/25 bg-gradient-to-b from-lime-950/30 to-black/50 p-3">
              <div className="flex items-center justify-between mb-2 px-1">
                <h2 className="text-sm font-bold text-white tracking-tight flex items-center gap-2">
                  <span>🎛️</span> {t('cicdSec.control_column', 'DevSecOps Control Column')}
                </h2>
                <button type="button" onClick={resetParams}
                  className="text-[9px] font-mono uppercase tracking-wide px-2 py-1 rounded-md border border-[var(--border-default)] text-[var(--text-muted)] hover:text-[var(--text-secondary)] hover:border-[var(--border-strong)] transition-colors">
                  {t('common.reset', 'Reset')}
                </button>
              </div>

              <Section title={t('cicdSec.sec_target', 'Target Binding')} icon="🎯" accent="#22d3ee" count={2}>
                <label className="block space-y-1">
                  <span className="text-[10px] font-mono text-[var(--text-muted)] uppercase tracking-wide">{t('common.client', 'Client')}</span>
                  <select value={selectedClientId} onChange={(e) => setSelectedClientId(e.target.value)}
                    className="w-full rounded-lg bg-[var(--bg-3)] border border-[var(--border-default)] px-3 py-1.5 text-sm text-white focus:outline-none focus:border-lime-400/40">
                    <option value="">—</option>
                    {clients.map((c) => <option key={c.id} value={c.id}>{c.name || c.id}</option>)}
                  </select>
                </label>
                <Txt label={t('common.target', 'Target')} value={target} onChange={setTarget} placeholder="https://ci.example.com" />
              </Section>

              <Section title={t('cicdSec.sec_scope', 'Probe Scope')} icon="🧩" accent="#84cc16" count={13}>
                <Sel label="Intensity" value={params.intensity} onChange={(v) => setField('intensity', v)} options={INTENSITIES} hint="Controls path depth & probe breadth" />
                <Toggle label="Platform Fingerprint" value={params.probe_fingerprint} onChange={(v) => setField('probe_fingerprint', v)} hint="Live HTTP banner / header detection" />
                <Toggle label="Unauthenticated API Exposure" value={params.probe_api} onChange={(v) => setField('probe_api', v)} />
                <Toggle label="Pipeline Config Exposure" value={params.probe_config} onChange={(v) => setField('probe_config', v)} hint="Jenkinsfile, .gitlab-ci.yml, workflows…" />
                <Toggle label="Build Log Exposure" value={params.probe_build_logs} onChange={(v) => setField('probe_build_logs', v)} hint="Jenkins Blue Ocean, GitLab job logs, build history" />
                <Toggle label="Artifact Registry Exposure" value={params.probe_artifact_exposure} onChange={(v) => setField('probe_artifact_exposure', v)} hint="Nexus, Artifactory, container _catalog, package APIs" />
                <Toggle label="Repository Plane (GitHub / GitLab / Bitbucket / Azure DevOps)" value={params.probe_repo} onChange={(v) => setField('probe_repo', v)} hint="Recursive CI/GitOps file fetch + static analysis" />
                <Toggle label="Repo Governance (GitHub + GitLab + Azure DevOps API)" value={params.probe_repo_governance} onChange={(v) => setField('probe_repo_governance', v)} hint="Branch protection, token defaults, fork-PR access, secret scanning — live API" />
                <Toggle label="Workflow Static Analysis" value={params.probe_workflow_analysis} onChange={(v) => setField('probe_workflow_analysis', v)} hint="pwn-request, injection, SLSA gaps, dependency confusion" />
                <Toggle label="Embedded Secret Scan (WZ-SEC-001)" value={params.probe_secret_scan} onChange={(v) => setField('probe_secret_scan', v)} hint="High-precision patterns in fetched pipeline artifacts" />
                <Toggle label="Runner Token Surface" value={params.probe_runner_tokens} onChange={(v) => setField('probe_runner_tokens', v)} />
                <Toggle label="Jenkins Script Console" value={params.probe_jenkins_console} onChange={(v) => setField('probe_jenkins_console', v)} />
                <Toggle label="Attack-Path Synthesis" value={params.attack_path_synthesis} onChange={(v) => setField('attack_path_synthesis', v)} hint="Wiz-style toxic combinations with path steps" />
                <Toggle label="Posture Scoring" value={params.posture_scoring} onChange={(v) => setField('posture_scoring', v)} />
              </Section>

              <Section title={t('cicdSec.sec_platforms', 'CI/CD Platforms')} icon="🏭" accent="#22d3ee" count={params.platform_filter.length} defaultOpen={false}>
                <div className="flex flex-wrap gap-1.5">
                  {PLATFORMS.map((p) => {
                    const on = params.platform_filter.includes(p.id)
                    return (
                      <button key={p.id} type="button" onClick={() => togglePlatform(p.id)}
                        className={`text-[10px] font-mono px-2 py-1 rounded-lg border transition-colors ${on ? 'border-lime-400/50 text-lime-200 bg-lime-500/15' : 'border-[var(--border-default)] text-[var(--text-muted)] hover:border-[var(--border-strong)]'}`}>
                        {p.icon} {p.label}
                      </button>
                    )
                  })}
                </div>
              </Section>

              <Section title={t('cicdSec.sec_repo', 'Repository Plane')} icon="🐙" accent="#a855f7" count={4} defaultOpen={false}>
                <Txt label="Repository URL" value={params.repo_url} onChange={(v) => setField('repo_url', v)} placeholder="https://github.com/org/repo · gitlab.com/group/project · dev.azure.com/org/proj/_git/repo" hint="Multi-vendor: GitHub, GitLab (incl. self-hosted), Bitbucket Cloud, Azure DevOps" />
                <Txt label="Ref / Branch" value={params.repo_ref} onChange={(v) => setField('repo_ref', v)} placeholder="main (auto-detect if empty)" />
                <Txt label="GitHub Token" value={params.github_token} onChange={(v) => setField('github_token', v)} type="password" hint="Optional — private repos + governance APIs" />
                <Txt label="Azure DevOps PAT" value={params.azure_devops_pat} onChange={(v) => setField('azure_devops_pat', v)} type="password" hint="Required for dev.azure.com repository plane & branch policies" />
              </Section>

              <Section title={t('cicdSec.sec_auth', 'Authentication')} icon="🔐" accent="#f59e0b" count={3} defaultOpen={false}>
                <Txt label="Bearer Token" value={params.bearer_token} onChange={(v) => setField('bearer_token', v)} type="password" />
                <Txt label="GitLab PRIVATE-TOKEN" value={params.gitlab_token} onChange={(v) => setField('gitlab_token', v)} type="password" />
                <Txt label="Custom Auth Header" value={params.auth_header} onChange={(v) => setField('auth_header', v)} placeholder="Authorization: Bearer …" />
              </Section>

              <Section title={t('cicdSec.sec_paths', 'Path Overrides')} icon="🛰️" accent="#34d399" count={2} defaultOpen={false}>
                <Area label="API Paths" value={params.api_paths} onChange={(v) => setField('api_paths', v)} rows={4}
                  placeholder={'one per line — empty = 14-platform default corpus\n/api/json\n/api/v4/runners'} />
                <Area label="Config Paths" value={params.config_paths} onChange={(v) => setField('config_paths', v)} rows={4}
                  placeholder={'/.github/workflows/ci.yml\n/Jenkinsfile'} />
              </Section>

              <Section title={t('cicdSec.sec_compliance', 'Compliance Mapping')} icon="📋" accent="#94a3b8" count={params.compliance_frameworks.length} defaultOpen={false}>
                <div className="flex flex-wrap gap-1.5">
                  {FRAMEWORKS.map((f) => {
                    const on = params.compliance_frameworks.includes(f)
                    return (
                      <button key={f} type="button" onClick={() => toggleFramework(f)}
                        className={`text-[9px] font-mono px-2 py-1 rounded-lg border transition-colors ${on ? 'border-cyan-400/40 text-cyan-200 bg-cyan-500/10' : 'border-[var(--border-default)] text-[var(--text-muted)]'}`}>
                        {f}
                      </button>
                    )
                  })}
                </div>
              </Section>

              <Section title={t('cicdSec.sec_transport', 'Transport & Limits')} icon="📡" accent="#38bdf8" count={4} defaultOpen={false}>
                <div className="grid grid-cols-2 gap-2">
                  <Num label="Timeout (ms)" value={params.timeout_ms} onChange={(v) => setField('timeout_ms', v)} min={500} max={60000} />
                  <Num label="Concurrency" value={params.max_concurrency} onChange={(v) => setField('max_concurrency', v)} min={1} max={64} />
                  <Num label="Max Requests" value={params.max_requests} onChange={(v) => setField('max_requests', v)} min={10} max={3000} />
                  <Num label="Max Repo CI Files" value={params.max_repo_files} onChange={(v) => setField('max_repo_files', v)} min={1} max={150} hint="GitHub tree fetch limit" />
                </div>
                <Sel label="Min Severity" value={params.min_severity} onChange={(v) => setField('min_severity', v)} options={SEVERITIES} />
                <Toggle label="Dry Run (plan only)" value={params.dry_run} onChange={(v) => setField('dry_run', v)} />
              </Section>

              <Section title={t('cicdSec.sec_payload', 'Live Payload Preview')} icon="📦" accent="#64748b" count={paramCount} defaultOpen={false}>
                <button type="button" onClick={() => setShowPreview((s) => !s)} className="text-[10px] font-mono text-lime-300/70 hover:text-lime-200">
                  {showPreview ? t('cicdSec.hide_json', 'hide JSON') : t('cicdSec.show_json', 'show exact request JSON')}
                </button>
                {showPreview && (
                  <pre className="max-h-60 overflow-auto rounded-lg bg-[var(--scrim)] border border-[var(--border-default)] p-2.5 text-[10px] font-mono text-emerald-300/80 leading-relaxed">
                    {JSON.stringify(previewBody, null, 2)}
                  </pre>
                )}
              </Section>

              <div className="mt-3 space-y-2">
                <button type="button" onClick={() => handleRun()} disabled={running || !selectedClientId || !target.trim()}
                  className="w-full py-3 rounded-xl font-mono text-sm uppercase tracking-widest border transition-all disabled:opacity-40 disabled:cursor-not-allowed"
                  style={{
                    borderColor: running ? 'rgba(132,204,22,0.5)' : 'rgba(132,204,22,0.6)',
                    background: running ? 'rgba(132,204,22,0.12)' : 'rgba(132,204,22,0.22)',
                    color: '#d9f99d',
                    boxShadow: running ? 'none' : '0 0 24px rgba(132,204,22,0.18)',
                  }}>
                  {running ? t('cicdSec.running', 'Assessing CI/CD…') : t('cicdSec.run', 'Run DevSecOps Scan')}
                </button>
                <button type="button" onClick={() => handleRun({ dryRun: true })} disabled={running || !selectedClientId || !target.trim()}
                  className="w-full py-2 rounded-xl font-mono text-[11px] uppercase tracking-widest border border-cyan-500/30 text-cyan-300 hover:bg-cyan-500/10 disabled:opacity-40 disabled:cursor-not-allowed transition-all">
                  {t('cicdSec.dry_run', 'Dry-Run Plan (no requests)')}
                </button>
              </div>
            </div>
          </div>

          <div className="space-y-6 min-w-0">
            <div className="grid grid-cols-1 2xl:grid-cols-3 gap-6">
              <div className="2xl:col-span-2 rounded-2xl border border-[var(--border-default)] bg-[var(--bg-2)] overflow-hidden">
                <div className="px-4 py-3 border-b border-[var(--border-subtle)] flex items-center justify-between">
                  <span className="text-[10px] font-mono uppercase tracking-[0.2em] text-[var(--text-muted)]">
                    {t('cicdSec.graph_viz', 'Supply Chain Attack Graph')}
                  </span>
                  {running && (
                    <span className="flex items-center gap-1.5 text-[10px] font-mono text-lime-300">
                      <span className="w-1.5 h-1.5 rounded-full bg-lime-400 animate-pulse" />
                      {params.dry_run ? 'PLANNING' : 'SCANNING'}
                    </span>
                  )}
                </div>
                <div className="h-72 md:h-80">
                  <SupplyChainGraphCanvas graph={metrics?.supply_chain_graph} running={running} />
                </div>
              </div>

              <div className="space-y-4">
                <div className="rounded-2xl border border-[var(--border-default)] bg-[var(--bg-2)] p-5 text-center">
                  <p className="text-[10px] font-mono uppercase tracking-[0.2em] text-[var(--text-muted)] mb-3">
                    {t('cicdSec.posture_score', 'DevSecOps Exposure Score')}
                  </p>
                  <PostureGauge score={metrics?.score} grade={metrics?.grade} />
                </div>
                <div className="grid grid-cols-2 gap-3">
                  <MetricTile label="Platforms" value={metrics?.platforms?.length ?? 0} accent="#22d3ee" />
                  <MetricTile label="API Exposed" value={metrics?.api_exposed} accent="#ef4444" />
                  <MetricTile label="Config Leaks" value={metrics?.config_exposed} accent="#f59e0b" />
                  <MetricTile label="Policy Violations" value={metrics?.workflow_violations} accent="#a855f7" />
                  <MetricTile label="Build Logs" value={metrics?.build_logs_exposed} accent="#fb923c" />
                  <MetricTile label="Artifacts" value={metrics?.artifact_exposed} accent="#f472b6" />
                  <MetricTile label="SLSA Gaps" value={metrics?.slsa_gaps} accent="#94a3b8" />
                  <MetricTile label="Secrets in Artifacts" value={metrics?.secrets_in_configs} accent="#ef4444" />
                  <MetricTile label="Attack Paths" value={attackPaths.length || '—'} accent="#84cc16" />
                </div>
                {metrics?.risk_dimensions && (
                  <div className="rounded-xl border border-[var(--border-default)] bg-[var(--bg-2)] p-3 space-y-2.5">
                    <p className="text-[9px] font-mono uppercase tracking-[0.2em] text-[var(--text-muted)]">{t('cicdSec.risk_dimensions', '5-Dimension Risk Model')}</p>
                    <RiskDimensionBar label="API Exposure" value={metrics.risk_dimensions.api_exposure} accent="#ef4444" />
                    <RiskDimensionBar label="Pipeline Integrity" value={metrics.risk_dimensions.pipeline_integrity} accent="#f59e0b" />
                    <RiskDimensionBar label="Secrets Leakage" value={metrics.risk_dimensions.secrets_leakage} accent="#f97316" />
                    <RiskDimensionBar label="Runner Isolation" value={metrics.risk_dimensions.runner_isolation} accent="#a855f7" />
                    <RiskDimensionBar label="Supply Chain" value={metrics.risk_dimensions.supply_chain} accent="#84cc16" />
                  </div>
                )}
                <PolicyHitsPanel policyHits={metrics?.policy_hits} />
                <CompliancePosturePanel compliancePosture={metrics?.compliance_posture} />
                <RemediationPlaybookPanel playbook={metrics?.remediation_playbook} />
                {metrics?.platforms?.length > 0 && (
                  <div className="rounded-xl border border-[var(--border-default)] bg-[var(--bg-2)] p-3">
                    <p className="text-[9px] font-mono uppercase tracking-[0.2em] text-[var(--text-muted)] mb-2">Detected Platforms</p>
                    <div className="flex flex-wrap gap-1.5">
                      {metrics.platforms.map((pid) => {
                        const p = PLATFORMS.find((x) => x.id === pid)
                        return (
                          <span key={pid} className="text-[10px] font-mono px-2 py-0.5 rounded border border-lime-500/30 text-lime-200 bg-lime-500/10">
                            {p?.icon} {p?.label || pid}
                          </span>
                        )
                      })}
                    </div>
                  </div>
                )}
              </div>
            </div>

            <AnimatePresence>
              {attackPaths.length > 0 && (
                <motion.div initial={{ opacity: 0 }} animate={{ opacity: 1 }}
                  className="rounded-2xl border border-lime-500/20 bg-lime-950/10 p-4 space-y-3">
                  <p className="text-[10px] font-mono text-lime-300/70 uppercase tracking-widest">
                    {t('cicdSec.attack_paths', 'Attack Paths (Toxic Combinations)')} · {attackPaths.length}
                  </p>
                  {attackPaths.map((p, i) => (
                    <div key={i} className="rounded-lg border border-[var(--border-default)] bg-[var(--bg-2)] p-3">
                      <div className="flex items-center gap-2 mb-1">
                        <span className="text-[10px] font-mono" style={sevColor(p.severity)}>[{p.severity}]</span>
                        <span className="text-sm font-semibold text-white">{p.title}</span>
                      </div>
                      {p.description && <p className="text-[10px] text-[var(--text-muted)] leading-snug">{p.description}</p>}
                      {Array.isArray(p.path_steps) && p.path_steps.length > 0 && (
                        <div className="flex flex-wrap items-center gap-1.5 mt-2">
                          {p.path_steps.map((step, j) => (
                            <React.Fragment key={j}>
                              <span className="text-[10px] font-mono text-[var(--text-tertiary)] rounded border border-[var(--border-default)] bg-[var(--bg-2)] px-1.5 py-0.5">{step}</span>
                              {j < p.path_steps.length - 1 && <span className="text-lime-400/60 text-xs">→</span>}
                            </React.Fragment>
                          ))}
                        </div>
                      )}
                    </div>
                  ))}
                </motion.div>
              )}
            </AnimatePresence>

            <div className="rounded-2xl border border-[var(--border-default)] bg-[var(--scrim)] overflow-hidden">
              <div className="px-4 py-2 border-b border-[var(--border-subtle)] text-[10px] font-mono text-[var(--text-muted)] uppercase tracking-widest">
                {t('cicdSec.telemetry', 'Scan Telemetry')}
              </div>
              <pre className="h-44 overflow-auto p-3 text-[10px] font-mono text-emerald-400/80 leading-relaxed">
                {lines.length ? lines.join('\n') : t('cicdSec.awaiting', 'Awaiting assessment…')}
              </pre>
            </div>

            <WeissmanFindingsPanel
              findings={realFindings}
              filteredFindings={filteredFindings}
              counts={counts}
              total={realFindings.length}
              searchQuery={searchQuery}
              onSearchChange={setSearchQuery}
              severityFilter={severityFilter}
              onSeverityChange={setSeverityFilter}
              pending={running && realFindings.length === 0}
              loading={historyLoading && realFindings.length === 0}
              lastUpdated={lastUpdated}
              jobId={lastJobId}
              accent="#84cc16"
              showEmptyReady={!running && realFindings.length === 0}
              emptyReadyTitle={t('cicdSec.no_findings', 'No findings yet — configure target and run scan.')}
              emptyReadyBody={t('cicdSec.awaiting', 'Awaiting assessment…')}
              renderFinding={(f, i) => (
                <div key={i} className="text-[11px] border-b border-[var(--border-subtle)] pb-2 last:border-0">
                  <div className="flex items-start gap-2">
                    <span className="font-mono shrink-0" style={sevColor(f.severity)}>[{f.severity || 'info'}]</span>
                    <span className="text-[var(--text-secondary)] min-w-0 font-semibold">{f.title}</span>
                  </div>
                  {f.description && <p className="text-[10px] text-[var(--text-muted)] ml-1 mt-0.5 leading-snug">{f.description}</p>}
                  <div className="flex flex-wrap gap-1.5 ml-1 mt-1">
                    {f.evidence?.policy && (
                      <span className="text-[9px] font-mono text-lime-300/70 rounded border border-lime-500/20 px-1.5 py-0.5">{f.evidence.policy}</span>
                    )}
                    {f.mitre_attack && (
                      <span className="text-[9px] font-mono text-[var(--text-disabled)] rounded border border-[var(--border-default)] px-1.5 py-0.5">{f.mitre_attack}</span>
                    )}
                  </div>
                </div>
              )}
            />
          </div>
        </div>
      </div>
    </PageShell>
  )
}
