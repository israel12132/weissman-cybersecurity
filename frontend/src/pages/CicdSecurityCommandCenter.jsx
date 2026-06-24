import React, { useState, useEffect, useRef, useCallback, useMemo } from 'react'
import { Link } from 'react-router-dom'
import { motion, AnimatePresence } from 'framer-motion'
import { useTranslation } from 'react-i18next'
import PageShell from './PageShell'
import ShellScanActions from '../components/engine/ShellScanActions'
import WeissmanFindingsPanel from '../components/engine/WeissmanFindingsPanel'
import { useWeissmanEnginePage, applyHistoryFindings } from '../hooks/useWeissmanEnginePage'
import { apiFetch, apiEventSourceUrl } from '../lib/apiBase'
import { ENGINES_BY_ID } from '../lib/enginesRegistry'

const ENGINE_ID = 'cicd_pipeline'
const ACCENT = '#84cc16'

const DEFAULT_PARAMS = {
  probe_fingerprint: true,
  probe_api: true,
  probe_config: true,
  probe_repo: true,
  probe_workflow_analysis: true,
  probe_runner_tokens: true,
  probe_jenkins_console: true,
  attack_path_synthesis: true,
  posture_scoring: true,
  repo_url: '',
  repo_ref: '',
  github_token: '',
  gitlab_token: '',
  bearer_token: '',
  auth_header: '',
  api_paths: '',
  config_paths: '',
  platform_filter: '',
  intensity: 'normal',
  timeout_ms: '10000',
  concurrency: '16',
  min_severity: 'info',
  max_requests: '600',
  dry_run: false,
  compliance_frameworks: 'NIST-SA-12,SOC2-CC8.1,PCI-DSS-6.3.2,MITRE-T1195.002',
}

const PLATFORMS = [
  { id: 'jenkins', label: 'Jenkins' },
  { id: 'gitlab', label: 'GitLab CI' },
  { id: 'argocd', label: 'ArgoCD' },
  { id: 'tekton', label: 'Tekton' },
  { id: 'azure_devops', label: 'Azure DevOps' },
  { id: 'github_actions', label: 'GitHub Actions (self-hosted)' },
  { id: 'drone', label: 'Drone CI' },
  { id: 'circleci', label: 'CircleCI' },
  { id: 'spinnaker', label: 'Spinnaker' },
  { id: 'teamcity', label: 'TeamCity' },
  { id: 'buildkite', label: 'Buildkite' },
  { id: 'harness', label: 'Harness' },
  { id: 'woodpecker', label: 'Woodpecker' },
  { id: 'bitbucket', label: 'Bitbucket' },
]

const ATTACK_REFERENCE = [
  { id: 'pwn-request', desc: 'pull_request_target + checkout head ref → org secret theft', sev: 'critical' },
  { id: 'jenkins-rce', desc: 'Unauthenticated Jenkins script console → build controller RCE', sev: 'critical' },
  { id: 'open-api', desc: 'ArgoCD/GitLab/Jenkins API without auth → pipeline injection', sev: 'critical' },
  { id: 'runner-token', desc: 'Registration token in API response → rogue runner', sev: 'critical' },
  { id: 'unpinned-action', desc: 'Third-party action @main/@v4 → supply-chain takeover', sev: 'high' },
  { id: 'script-inj', desc: 'github.event.* in run: step → runner command injection', sev: 'high' },
]

const splitLines = (s) => String(s || '').split('\n').map((x) => x.trim()).filter(Boolean)
const splitCsv = (s) => String(s || '').split(',').map((x) => x.trim()).filter(Boolean)
const numOr = (v, d) => { const n = Number(v); return Number.isFinite(n) ? n : d }

function buildScanBody(params, clientId, target) {
  const body = {
    engine: ENGINE_ID,
    client_id: Number(clientId),
    target: (target || '').trim(),
    timeout: 300,
    probe_fingerprint: !!params.probe_fingerprint,
    probe_api: !!params.probe_api,
    probe_config: !!params.probe_config,
    probe_repo: !!params.probe_repo,
    probe_workflow_analysis: !!params.probe_workflow_analysis,
    probe_runner_tokens: !!params.probe_runner_tokens,
    probe_jenkins_console: !!params.probe_jenkins_console,
    attack_path_synthesis: !!params.attack_path_synthesis,
    posture_scoring: !!params.posture_scoring,
    intensity: params.intensity,
    timeout_ms: numOr(params.timeout_ms, 10000),
    concurrency: numOr(params.concurrency, 16),
    min_severity: params.min_severity,
    max_requests: numOr(params.max_requests, 600),
    dry_run: !!params.dry_run,
  }
  if (params.repo_url.trim()) body.repo_url = params.repo_url.trim()
  if (params.repo_ref.trim()) body.repo_ref = params.repo_ref.trim()
  if (params.github_token.trim()) body.github_token = params.github_token.trim()
  if (params.gitlab_token.trim()) body.gitlab_token = params.gitlab_token.trim()
  if (params.bearer_token.trim()) body.bearer_token = params.bearer_token.trim()
  if (params.auth_header.trim()) body.auth_header = params.auth_header.trim()
  const ap = splitLines(params.api_paths)
  if (ap.length) body.api_paths = ap
  const cp = splitLines(params.config_paths)
  if (cp.length) body.config_paths = cp
  const pf = splitCsv(params.platform_filter)
  if (pf.length) body.platform_filter = pf
  const fw = splitCsv(params.compliance_frameworks)
  if (fw.length) body.compliance_frameworks = fw
  return body
}

function Section({ title, icon, accent = ACCENT, count, defaultOpen = true, children }) {
  const [open, setOpen] = useState(defaultOpen)
  return (
    <div className="rounded-xl border border-white/10 bg-black/30 overflow-hidden" style={{ borderColor: `${accent}22` }}>
      <button type="button" onClick={() => setOpen((o) => !o)} className="w-full flex items-center justify-between px-3 py-2.5 hover:bg-white/[0.03] transition-colors">
        <span className="flex items-center gap-2 text-[11px] font-mono uppercase tracking-[0.18em] font-semibold" style={{ color: accent }}>
          <span>{icon}</span>{title}{count != null && <span className="text-white/30 normal-case tracking-normal">· {count}</span>}
        </span>
        <span className={`text-white/40 text-xs transition-transform ${open ? 'rotate-90' : ''}`}>▶</span>
      </button>
      {open && <div className="px-3 pb-3 pt-1 space-y-3 border-t border-white/5">{children}</div>}
    </div>
  )
}

function Toggle({ label, hint, checked, onChange }) {
  return (
    <button type="button" onClick={() => onChange(!checked)} className="w-full flex items-center justify-between gap-3 px-2 py-1.5 rounded-lg hover:bg-white/5 transition-colors text-left">
      <span className="min-w-0">
        <span className="block text-[11px] font-mono text-white/85">{label}</span>
        {hint && <span className="block text-[9px] font-mono text-white/30">{hint}</span>}
      </span>
      <span className={`shrink-0 w-8 h-4 rounded-full relative transition-colors ${checked ? 'bg-lime-500/60' : 'bg-white/15'}`}>
        <span className={`absolute top-0.5 w-3 h-3 rounded-full bg-white transition-all ${checked ? 'left-[18px]' : 'left-0.5'}`} />
      </span>
    </button>
  )
}

function Txt({ label, value, onChange, placeholder, hint, type = 'text' }) {
  return (
    <label className="block space-y-1">
      <span className="text-[10px] font-mono text-white/45 uppercase tracking-wide">{label}</span>
      <input type={type} value={value} onChange={(e) => onChange(e.target.value)} placeholder={placeholder}
        className="w-full rounded-lg bg-black/50 border border-white/10 px-3 py-1.5 text-sm text-white font-mono placeholder-white/20 focus:outline-none focus:border-lime-400/40" />
      {hint && <span className="text-[9px] font-mono text-white/25">{hint}</span>}
    </label>
  )
}

function Area({ label, value, onChange, placeholder, rows = 3, hint }) {
  return (
    <label className="block space-y-1">
      <span className="text-[10px] font-mono text-white/45 uppercase tracking-wide">{label}</span>
      <textarea value={value} onChange={(e) => onChange(e.target.value)} rows={rows} placeholder={placeholder}
        className="w-full rounded-lg bg-black/50 border border-white/10 px-3 py-1.5 text-xs text-white font-mono placeholder-white/20 focus:outline-none focus:border-lime-400/40 resize-y" />
      {hint && <span className="text-[9px] font-mono text-white/25">{hint}</span>}
    </label>
  )
}

function Segmented({ label, value, options, onChange }) {
  return (
    <div>
      {label && <p className="text-[10px] font-mono text-white/40 uppercase tracking-widest mb-1.5">{label}</p>}
      <div className="flex rounded-lg bg-black/40 border border-white/10 p-0.5 gap-0.5">
        {options.map((o) => (
          <button key={o.value} type="button" onClick={() => onChange(o.value)}
            className={`flex-1 px-2 py-1.5 rounded-md text-[10px] font-mono transition-all ${value === o.value ? 'bg-lime-500/20 text-lime-300 border border-lime-400/40' : 'text-white/45 hover:text-white/70 border border-transparent'}`}>
            {o.label}
          </button>
        ))}
      </div>
    </div>
  )
}

const SEV_META = {
  critical: { color: '#ef4444', border: 'border-red-500/40', bg: 'bg-red-950/30', text: 'text-red-300' },
  high: { color: '#f97316', border: 'border-orange-500/40', bg: 'bg-orange-950/30', text: 'text-orange-300' },
  medium: { color: '#f59e0b', border: 'border-amber-500/30', bg: 'bg-amber-950/20', text: 'text-amber-300' },
  low: { color: '#38bdf8', border: 'border-sky-500/30', bg: 'bg-sky-950/20', text: 'text-sky-300' },
  info: { color: '#4ade80', border: 'border-emerald-500/30', bg: 'bg-emerald-950/20', text: 'text-emerald-300' },
}

function FindingRow({ f }) {
  const [open, setOpen] = useState(false)
  const sev = (f.severity || 'info').toLowerCase()
  const meta = SEV_META[sev] || SEV_META.info
  const conf = typeof f.confidence === 'number' ? Math.round(f.confidence * 100) : null
  return (
    <div className={`rounded-xl border ${meta.border} ${meta.bg} overflow-hidden`}>
      <button type="button" onClick={() => setOpen((o) => !o)} className="w-full flex items-start gap-3 px-3 py-2.5 text-left hover:bg-white/5 transition-colors">
        <span className={`text-[9px] font-mono px-1.5 py-0.5 rounded border uppercase shrink-0 ${meta.text} ${meta.border}`}>{sev}</span>
        <span className="min-w-0 flex-1">
          <span className="block text-[12px] font-mono text-white/90">{f.title || f.type}</span>
          {!open && <span className="block text-[10px] font-mono text-white/40 truncate mt-0.5">{f.description}</span>}
        </span>
        {conf !== null && <span className="text-[10px] font-mono text-white/35 shrink-0">{conf}%</span>}
        <span className="text-white/30 text-xs shrink-0">{open ? '▾' : '▸'}</span>
      </button>
      <AnimatePresence initial={false}>
        {open && (
          <motion.div initial={{ height: 0, opacity: 0 }} animate={{ height: 'auto', opacity: 1 }} exit={{ height: 0, opacity: 0 }} className="px-3 pb-3">
            <p className="text-[11px] font-mono text-white/55 leading-relaxed">{f.description}</p>
            {f.evidence && (
              <pre className="mt-2 text-[10px] font-mono text-white/40 bg-black/40 rounded-lg p-2 overflow-x-auto max-h-48">
                {JSON.stringify(f.evidence, null, 2)}
              </pre>
            )}
          </motion.div>
        )}
      </AnimatePresence>
    </div>
  )
}

export default function CicdSecurityCommandCenter() {
  const { t } = useTranslation()
  const engine = ENGINES_BY_ID[ENGINE_ID]
  const [clients, setClients] = useState([])
  const [selectedClientId, setSelectedClientId] = useState('')
  const [target, setTarget] = useState('')
  const [params, setParams] = useState(DEFAULT_PARAMS)
  const [running, setRunning] = useState(false)
  const [lines, setLines] = useState([])
  const [metrics, setMetrics] = useState(null)
  const [findings, setFindings] = useState([])
  const esRef = useRef(null)

  const setField = useCallback((key, val) => setParams((p) => ({ ...p, [key]: val })), [])
  const resetParams = useCallback(() => setParams({ ...DEFAULT_PARAMS }), [])

  const previewBody = useMemo(() => buildScanBody(params, selectedClientId || 0, target), [params, selectedClientId, target])
  const paramCount = useMemo(() => Object.keys(previewBody).length, [previewBody])
  const attackPaths = useMemo(() => findings.filter((f) => f.category === 'attack_path'), [findings])
  const realFindings = useMemo(() => findings.filter((f) => !['attack_path', 'cicd_metrics', 'dry_run'].includes(f.category)), [findings])

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
      const r = await apiFetch('/api/command-center/scan', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body) })
      const data = await r.json()
      if (!r.ok) { appendLine(`[ERROR] ${data.detail || 'Scan failed'}`); setRunning(false); return }
      const jobId = data.job_id
      appendLine(`[CI/CD] Job queued: ${jobId}`)
      if (esRef.current) esRef.current.close()
      const es = new EventSource(apiEventSourceUrl(`/api/telemetry/stream?job_id=${jobId}`))
      esRef.current = es
      es.onmessage = (ev) => {
        try {
          const p = JSON.parse(ev.data)
          if (p.message) appendLine(p.message)
          if (p.status === 'completed' || p.status === 'failed') {
            es.close()
            setRunning(false)
            apiFetch(`/api/jobs/${jobId}`).then((jr) => (jr.ok ? jr.json() : null)).then((job) => {
              const res = job?.result_json || job?.result
              const f = res?.findings || []
              setFindings(f)
              setLastUpdated(new Date().toISOString())
              if (jobId) setLastJobId(jobId)
              const meta = f.find((x) => x.cicd_metrics)?.cicd_metrics
              if (meta) setMetrics(meta)
              appendLine(`[CI/CD] ${dryRun ? 'Dry-run complete' : 'Assessment complete'} — ${f.length} findings`)
            }).catch(() => {})
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
      title={t('cicdSec.title', 'CI/CD Security Command Center')}
      subtitle={t('cicdSec.subtitle', 'Agentless DevSecOps — Jenkins, GitLab, ArgoCD, GitHub Actions — Wiz-grade pipeline posture & attack-path synthesis')}
      badge="DevSecOps"
      badgeColor={ACCENT}
      icon="⚙"
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
          <div className="relative flex flex-wrap items-center justify-between gap-4">
            <div>
              <div className="flex items-center gap-2 mb-2 flex-wrap">
                <span className="text-[10px] font-mono px-2 py-0.5 rounded-full border border-lime-400/40 text-lime-300 bg-lime-500/10 uppercase tracking-widest">Pipeline Security · ⚙</span>
                <span className="text-[10px] font-mono px-2 py-0.5 rounded-full border border-emerald-400/30 text-emerald-300 bg-emerald-500/10 uppercase tracking-widest">{paramCount} live parameters</span>
                <span className="text-[10px] font-mono text-white/30">MITRE T1195.002 · T1552.004</span>
              </div>
              <p className="text-sm text-white/60 max-w-2xl font-mono leading-relaxed">
                {t('cicdSec.hero_desc', 'Evidence-only remote assessment: unauthenticated CI/CD APIs, exposed Jenkinsfile/workflows, GitHub Actions pwn-request & script-injection static analysis — every finding backed by a real HTTP or repository signal.')}
              </p>
            </div>
            {metrics && (
              <div className="flex gap-4">
                <div className="text-center px-4 py-2 rounded-xl bg-black/40 border border-lime-500/30">
                  <div className="text-2xl font-bold font-mono text-lime-300">{metrics.score ?? '—'}</div>
                  <div className="text-[9px] font-mono text-white/40 uppercase">Posture</div>
                </div>
                <div className="text-center px-4 py-2 rounded-xl bg-black/40 border border-white/10">
                  <div className="text-2xl font-bold font-mono text-white">{metrics.grade ?? '—'}</div>
                  <div className="text-[9px] font-mono text-white/40 uppercase">Grade</div>
                </div>
              </div>
            )}
          </div>
        </motion.div>

        <div className="grid grid-cols-1 xl:grid-cols-[340px_1fr] gap-6">
          <aside className="space-y-4">
            <div className="rounded-2xl border border-white/10 bg-black/40 p-4 space-y-3">
              <h2 className="text-sm font-bold text-white tracking-tight flex items-center gap-2"><span>🎛️</span> {t('cicdSec.control', 'Pipeline Control Column')}</h2>
              <label className="block space-y-1">
                <span className="text-[10px] font-mono text-white/45 uppercase">Client</span>
                <select value={selectedClientId} onChange={(e) => setSelectedClientId(e.target.value)}
                  className="w-full rounded-lg bg-black/50 border border-white/10 px-3 py-2 text-sm text-white font-mono">
                  <option value="">— select —</option>
                  {clients.map((c) => <option key={c.id} value={c.id}>{c.name || c.company_name || `Client ${c.id}`}</option>)}
                </select>
              </label>
              <Txt label="Target URL" value={target} onChange={(v) => setTarget(v)} placeholder="https://ci.example.com" hint="CI/CD server or app hosting pipeline configs" />
              <Link to={`/engines/${ENGINE_ID}`} className="text-[10px] font-mono text-lime-400/70 hover:text-lime-300">{engine?.label || ENGINE_ID} → engine profile</Link>
            </div>

            <div className="rounded-2xl border border-white/10 bg-black/40 p-3 space-y-3 max-h-[70vh] overflow-y-auto">
              <Section title={t('cicdSec.scope', 'Probe Scope')} icon="🧩" count={8}>
                <Toggle label="CI/CD API Exposure" checked={params.probe_api} onChange={(v) => setField('probe_api', v)} hint="Jenkins, GitLab, ArgoCD, Tekton, Azure DevOps…" />
                <Toggle label="Pipeline Config Exposure" checked={params.probe_config} onChange={(v) => setField('probe_config', v)} hint="Jenkinsfile, .gitlab-ci.yml, workflows" />
                <Toggle label="GitHub Repo Analysis" checked={params.probe_repo} onChange={(v) => setField('probe_repo', v)} hint="Fetch workflows from github.com/org/repo" />
                <Toggle label="Workflow Static Analysis" checked={params.probe_workflow_analysis} onChange={(v) => setField('probe_workflow_analysis', v)} hint="pwn-request, script injection, unpinned actions" />
                <Toggle label="Runner Token Detection" checked={params.probe_runner_tokens} onChange={(v) => setField('probe_runner_tokens', v)} />
                <Toggle label="Jenkins Script Console" checked={params.probe_jenkins_console} onChange={(v) => setField('probe_jenkins_console', v)} hint="/script Groovy console probe" />
                <Toggle label="Attack-Path Synthesis" checked={params.attack_path_synthesis} onChange={(v) => setField('attack_path_synthesis', v)} />
                <Toggle label="Posture Scoring" checked={params.posture_scoring} onChange={(v) => setField('posture_scoring', v)} />
              </Section>

              <Section title={t('cicdSec.repo', 'Repository Plane')} icon="🐙" defaultOpen={false}>
                <Txt label="GitHub Repo URL" value={params.repo_url} onChange={(v) => setField('repo_url', v)} placeholder="https://github.com/org/repo" />
                <Txt label="Ref / Branch" value={params.repo_ref} onChange={(v) => setField('repo_ref', v)} placeholder="main (default branch if empty)" />
                <Txt label="GitHub Token" value={params.github_token} onChange={(v) => setField('github_token', v)} type="password" hint="Optional — private repos" />
                <Txt label="GitLab Token" value={params.gitlab_token} onChange={(v) => setField('gitlab_token', v)} type="password" hint="PRIVATE-TOKEN for GitLab API probes" />
              </Section>

              <Section title={t('cicdSec.platforms', 'Platform Filter')} icon="🏗" defaultOpen={false}>
                <Area label="Platform IDs (comma-sep, blank = all)" value={params.platform_filter} onChange={(v) => setField('platform_filter', v)} placeholder={PLATFORMS.map((p) => p.id).join(', ')} rows={2} />
              </Section>

              <Section title={t('cicdSec.paths', 'Path Corpora')} icon="📂" defaultOpen={false}>
                <Area label="API Paths (override)" value={params.api_paths} onChange={(v) => setField('api_paths', v)} placeholder="/api/json\n/api/v4/runners" rows={3} />
                <Area label="Config Paths (override)" value={params.config_paths} onChange={(v) => setField('config_paths', v)} placeholder=".github/workflows/ci.yml\nJenkinsfile" rows={3} />
              </Section>

              <Section title={t('cicdSec.tuning', 'Tuning & Auth')} icon="⚙" defaultOpen={false}>
                <Segmented label="Intensity" value={params.intensity} onChange={(v) => setField('intensity', v)} options={[{ value: 'light', label: 'Light' }, { value: 'normal', label: 'Normal' }, { value: 'aggressive', label: 'Aggressive' }]} />
                <Txt label="Timeout (ms)" value={params.timeout_ms} onChange={(v) => setField('timeout_ms', v)} />
                <Txt label="Concurrency" value={params.concurrency} onChange={(v) => setField('concurrency', v)} />
                <Txt label="Bearer Token" value={params.bearer_token} onChange={(v) => setField('bearer_token', v)} type="password" />
                <Txt label="Auth Header" value={params.auth_header} onChange={(v) => setField('auth_header', v)} placeholder="Authorization: Bearer …" />
                <Txt label="Min Severity" value={params.min_severity} onChange={(v) => setField('min_severity', v)} />
                <Txt label="Compliance Frameworks" value={params.compliance_frameworks} onChange={(v) => setField('compliance_frameworks', v)} />
                <Toggle label="Dry Run" checked={params.dry_run} onChange={(v) => setField('dry_run', v)} />
              </Section>

              <div className="flex gap-2 pt-1">
                <button type="button" disabled={running || !selectedClientId || !target.trim()} onClick={() => handleRun()}
                  className="flex-1 py-2.5 rounded-xl font-mono text-sm font-semibold bg-lime-600/80 hover:bg-lime-500/90 text-black disabled:opacity-40 transition-colors">
                  {running ? t('common.running', 'Running…') : t('cicdSec.run', 'Run CI/CD Scan')}
                </button>
                <button type="button" disabled={running} onClick={() => handleRun({ dryRun: true })}
                  className="px-3 py-2.5 rounded-xl font-mono text-xs border border-white/15 text-white/60 hover:bg-white/5 disabled:opacity-40">Dry</button>
                <button type="button" onClick={resetParams} className="px-3 py-2.5 rounded-xl font-mono text-xs border border-white/15 text-white/40 hover:bg-white/5">Reset</button>
              </div>
            </div>
          </aside>

          <main className="space-y-4 min-w-0">
            {attackPaths.length > 0 && (
              <div className="rounded-2xl border border-red-500/30 bg-red-950/20 p-4">
                <h3 className="text-sm font-mono text-red-300 uppercase tracking-widest mb-3">⚠ Attack Paths ({attackPaths.length})</h3>
                <div className="space-y-2">{attackPaths.map((f, i) => <FindingRow key={i} f={f} />)}</div>
              </div>
            )}

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
              accent={ACCENT}
              showEmptyReady={!running && realFindings.length === 0}
              emptyReadyTitle={t('cicdSec.no_findings', 'No findings yet — configure target and run scan.')}
              renderFinding={(f, i) => <FindingRow key={i} f={f} />}
            />

            <div className="rounded-2xl border border-white/10 bg-black/40 p-4">
              <h3 className="text-sm font-mono text-white/60 uppercase tracking-widest mb-2">{t('cicdSec.telemetry', 'Live Telemetry')}</h3>
              <pre className="text-[10px] font-mono text-white/45 bg-black/50 rounded-lg p-3 max-h-36 overflow-y-auto whitespace-pre-wrap">{lines.join('\n') || '—'}</pre>
            </div>

            <div className="rounded-2xl border border-white/10 bg-black/40 p-4">
              <h3 className="text-sm font-mono text-white/60 uppercase tracking-widest mb-3">{t('cicdSec.reference', 'Attack Reference')}</h3>
              <div className="grid grid-cols-1 sm:grid-cols-2 gap-2">
                {ATTACK_REFERENCE.map((r) => (
                  <div key={r.id} className="px-3 py-2 rounded-lg bg-black/30 border border-white/5">
                    <span className={`text-[9px] font-mono uppercase ${SEV_META[r.sev]?.text || 'text-white/50'}`}>{r.sev}</span>
                    <p className="text-[10px] font-mono text-white/55 mt-0.5">{r.desc}</p>
                  </div>
                ))}
              </div>
            </div>
          </main>
        </div>
      </div>
    </PageShell>
  )
}
