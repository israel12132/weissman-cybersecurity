import { useCommandCenterScan } from '../hooks/useCommandCenterScan'
import { useSyncHubScanParams } from '../hooks/useLaunchEngineScan'
import { useState, useEffect, useRef, useCallback, useMemo } from 'react'
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

const ENGINE_ID = 'serverless_attack'
const ACCENT = '#ec4899'

const DEFAULT_PARAMS = {
  probe_fingerprint: true,
  probe_functions: true,
  probe_config: true,
  probe_env_leak: true,
  probe_cors: true,
  probe_event_injection: true,
  probe_cold_start: true,
  probe_admin: true,
  attack_path_synthesis: true,
  posture_scoring: true,
  function_paths: '',
  config_paths: '',
  debug_paths: '',
  platform_filter: '',
  intensity: 'normal',
  timeout_ms: '8000',
  concurrency: '16',
  cold_start_samples: '3',
  cors_test_origin: 'https://evil-attacker.example',
  min_severity: 'info',
  max_requests: '500',
  user_agent: '',
  bearer_token: '',
  auth_header: '',
  dry_run: false,
  extra_headers: [{ name: 'Authorization', value: '' }],
}

const PLATFORMS = [
  { id: 'aws_lambda', label: 'AWS Lambda' },
  { id: 'azure_functions', label: 'Azure Functions' },
  { id: 'gcp_cloud_functions', label: 'GCP Cloud Functions' },
  { id: 'vercel', label: 'Vercel' },
  { id: 'netlify', label: 'Netlify' },
  { id: 'cloudflare_workers', label: 'Cloudflare Workers' },
  { id: 'firebase', label: 'Firebase' },
  { id: 'openfaas', label: 'OpenFaaS / Knative' },
]

const ATTACK_REFERENCE = [
  { id: 'env-leak', desc: 'Debug endpoint exposes DATABASE_URL / AWS_* env vars', sev: 'critical' },
  { id: 'cors', desc: 'Function URL wildcard CORS → cross-origin data theft', sev: 'high' },
  { id: 'iac', desc: 'serverless.yml / template.yaml web-accessible', sev: 'high' },
  { id: 'event-inj', desc: 'Malformed Lambda event → stack trace disclosure', sev: 'high' },
  { id: 'admin', desc: 'Unauthenticated /api/admin or /_admin console', sev: 'critical' },
  { id: 'cold-start', desc: 'Timing differential confirms ephemeral FaaS runtime', sev: 'info' },
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
    probe_functions: !!params.probe_functions,
    probe_config: !!params.probe_config,
    probe_env_leak: !!params.probe_env_leak,
    probe_cors: !!params.probe_cors,
    probe_event_injection: !!params.probe_event_injection,
    probe_cold_start: !!params.probe_cold_start,
    probe_admin: !!params.probe_admin,
    attack_path_synthesis: !!params.attack_path_synthesis,
    posture_scoring: !!params.posture_scoring,
    intensity: params.intensity,
    timeout_ms: numOr(params.timeout_ms, 8000),
    concurrency: numOr(params.concurrency, 16),
    cold_start_samples: numOr(params.cold_start_samples, 3),
    cors_test_origin: params.cors_test_origin.trim() || 'https://evil-attacker.example',
    min_severity: params.min_severity,
    max_requests: numOr(params.max_requests, 500),
    dry_run: !!params.dry_run,
  }
  const fp = splitLines(params.function_paths)
  if (fp.length) body.function_paths = fp
  const cp = splitLines(params.config_paths)
  if (cp.length) body.config_paths = cp
  const dp = splitLines(params.debug_paths)
  if (dp.length) body.debug_paths = dp
  const pf = splitCsv(params.platform_filter)
  if (pf.length) body.platform_filter = pf
  if (params.user_agent.trim()) body.user_agent = params.user_agent.trim()
  if (params.bearer_token.trim()) body.bearer_token = params.bearer_token.trim()
  if (params.auth_header.trim()) body.auth_header = params.auth_header.trim()
  const hdrs = {}
  for (const h of params.extra_headers) {
    if (h.name.trim() && h.value.trim()) hdrs[h.name.trim()] = h.value.trim()
  }
  if (Object.keys(hdrs).length) body.extra_headers = hdrs
  return body
}

function Section({ title, icon, accent = ACCENT, count, defaultOpen = true, children }) {
  const [open, setOpen] = useState(defaultOpen)
  return (
    <div className="rounded-xl border border-[var(--border-default)] bg-[var(--table-surface)] overflow-hidden" style={{ borderColor: `${accent}22` }}>
      <button type="button" onClick={() => setOpen((o) => !o)} className="w-full flex items-center justify-between px-3 py-2.5 hover:bg-[var(--row-hover-bg)] transition-colors">
        <span className="flex items-center gap-2 text-[11px] font-mono uppercase tracking-[0.18em] font-semibold" style={{ color: accent }}>
          <span>{icon}</span>{title}{count != null && <span className="text-[var(--text-disabled)] normal-case tracking-normal">· {count}</span>}
        </span>
        <span className={`text-[var(--text-muted)] text-xs transition-transform ${open ? 'rotate-90' : ''}`}>▶</span>
      </button>
      {open && <div className="px-3 pb-3 pt-1 space-y-3 border-t border-[var(--border-subtle)]">{children}</div>}
    </div>
  )
}

function Toggle({ label, hint, checked, onChange }) {
  return (
    <button type="button" onClick={() => onChange(!checked)} className="w-full flex items-center justify-between gap-3 px-2 py-1.5 rounded-lg hover:bg-[var(--row-hover-bg)] transition-colors text-left">
      <span className="min-w-0">
        <span className="block text-[11px] font-mono text-[var(--text-primary)]">{label}</span>
        {hint && <span className="block text-[9px] font-mono text-[var(--text-disabled)]">{hint}</span>}
      </span>
      <span className={`shrink-0 w-8 h-4 rounded-full relative transition-colors ${checked ? 'bg-pink-500/60' : 'bg-white/15'}`}>
        <span className={`absolute top-0.5 w-3 h-3 rounded-full bg-white transition-all ${checked ? 'left-[18px]' : 'left-0.5'}`} />
      </span>
    </button>
  )
}

function Txt({ label, value, onChange, placeholder, hint }) {
  return (
    <label className="block space-y-1">
      <span className="text-[10px] font-mono text-[var(--text-muted)] uppercase tracking-wide">{label}</span>
      <input value={value} onChange={(e) => onChange(e.target.value)} placeholder={placeholder}
        className="w-full rounded-lg bg-[var(--bg-3)] border border-[var(--border-default)] px-3 py-1.5 text-sm text-white font-mono placeholder-white/20 focus:outline-none focus:border-pink-400/40" />
      {hint && <span className="text-[9px] font-mono text-[var(--text-disabled)]">{hint}</span>}
    </label>
  )
}

function Area({ label, value, onChange, placeholder, rows = 3, hint }) {
  return (
    <label className="block space-y-1">
      <span className="text-[10px] font-mono text-[var(--text-muted)] uppercase tracking-wide">{label}</span>
      <textarea value={value} onChange={(e) => onChange(e.target.value)} rows={rows} placeholder={placeholder}
        className="w-full rounded-lg bg-[var(--bg-3)] border border-[var(--border-default)] px-3 py-1.5 text-xs text-white font-mono placeholder-white/20 focus:outline-none focus:border-pink-400/40 resize-y" />
      {hint && <span className="text-[9px] font-mono text-[var(--text-disabled)]">{hint}</span>}
    </label>
  )
}

function Segmented({ label, value, options, onChange }) {
  return (
    <div>
      {label && <p className="text-[10px] font-mono text-[var(--text-muted)] uppercase tracking-widest mb-1.5">{label}</p>}
      <div className="flex rounded-lg bg-[var(--bg-2)] border border-[var(--border-default)] p-0.5 gap-0.5">
        {options.map((o) => (
          <button key={o.value} type="button" onClick={() => onChange(o.value)}
            className={`flex-1 px-2 py-1.5 rounded-md text-[10px] font-mono transition-all ${value === o.value ? 'bg-pink-500/20 text-pink-300 border border-pink-400/40' : 'text-[var(--text-muted)] hover:text-[var(--text-secondary)] border border-transparent'}`}>
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
      <button type="button" onClick={() => setOpen((o) => !o)} className="w-full flex items-start gap-3 px-3 py-2.5 text-left hover:bg-[var(--row-hover-bg)] transition-colors">
        <span className={`text-[9px] font-mono px-1.5 py-0.5 rounded border uppercase shrink-0 ${meta.text} ${meta.border}`}>{sev}</span>
        <span className="min-w-0 flex-1">
          <span className="block text-[12px] font-mono text-[var(--text-primary)]">{f.title || f.type}</span>
          {!open && <span className="block text-[10px] font-mono text-[var(--text-muted)] truncate mt-0.5">{f.description}</span>}
        </span>
        {conf !== null && <span className="text-[10px] font-mono text-[var(--text-muted)] shrink-0">{conf}%</span>}
        <span className="text-[var(--text-disabled)] text-xs shrink-0">{open ? '▾' : '▸'}</span>
      </button>
      <AnimatePresence initial={false}>
        {open && (
          <motion.div initial={{ height: 0, opacity: 0 }} animate={{ height: 'auto', opacity: 1 }} exit={{ height: 0, opacity: 0 }} className="px-3 pb-3">
            <p className="text-[11px] font-mono text-[var(--text-tertiary)] leading-relaxed">{f.description}</p>
            {f.evidence && (
              <pre className="mt-2 text-[10px] font-mono text-[var(--text-muted)] bg-[var(--bg-2)] rounded-lg p-2 overflow-x-auto max-h-48">
                {JSON.stringify(f.evidence, null, 2)}
              </pre>
            )}
          </motion.div>
        )}
      </AnimatePresence>
    </div>
  )
}

export default function ServerlessSecurityCommandCenter() {
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
  const esRef = useRef(null)

  const setField = useCallback((key, val) => setParams((p) => ({ ...p, [key]: val })), [])
  const setHeader = useCallback((i, field, val) => {
    setParams((p) => ({ ...p, extra_headers: p.extra_headers.map((h, idx) => (idx === i ? { ...h, [field]: val } : h)) }))
  }, [])
  const addHeader = useCallback(() => {
    setParams((p) => ({ ...p, extra_headers: [...p.extra_headers, { name: '', value: '' }] }))
  }, [])
  const removeHeader = useCallback((i) => {
    setParams((p) => ({ ...p, extra_headers: p.extra_headers.filter((_, idx) => idx !== i) }))
  }, [])
  const resetParams = useCallback(() => setParams({ ...DEFAULT_PARAMS, extra_headers: [{ name: 'Authorization', value: '' }] }), [])

  const previewBody = useMemo(() => buildScanBody(params, selectedClientId || 0, target), [params, selectedClientId, target])
  const paramCount = useMemo(() => Object.keys(previewBody).length, [previewBody])
  const attackPaths = useMemo(() => findings.filter((f) => f.category === 'attack_path'), [findings])
  const realFindings = useMemo(() => findings.filter((f) => !['attack_path', 'serverless_metrics', 'dry_run'].includes(f.category)), [findings])

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
        const meta = run.findings.find((x) => x.serverless_metrics)?.serverless_metrics
        if (meta) setMetrics(meta)
      }
    })
  }, [refreshFromHistory, setLastUpdated, setLastJobId])

  const handleRefresh = useCallback(async () => {
    const run = await refreshFromHistory()
    if (applyHistoryFindings(run, setFindings, { setLastUpdated, setJobId: setLastJobId })) {
      const meta = run.findings.find((x) => x.serverless_metrics)?.serverless_metrics
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
    appendLine(`[λ] ${dryRun ? 'Planning dry-run' : 'Launching serverless security assessment'} — ${paramCount} params…`)
    const body = buildScanBody(params, selectedClientId, target)
    if (opts.dryRun) body.dry_run = true
    try {
      const { ok, data } = await postScan(body)
      if (!ok) { appendLine(`[ERROR] ${data.detail || 'Scan failed'}`); setRunning(false); return }
      const jobId = data.job_id
      appendLine(`[λ] Job queued: ${jobId}`)
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
            apiFetch(`/api/jobs/${jobId}`).then((jr) => (jr.ok ? jr.json() : null)).then((job) => {
              const res = job?.result_json || job?.result
              const f = res?.findings || []
              setFindings(f)
              setLastUpdated(new Date().toISOString())
              if (jobId) setLastJobId(jobId)
              const meta = f.find((x) => x.serverless_metrics)?.serverless_metrics
              if (meta) setMetrics(meta)
              appendLine(`[λ] ${dryRun ? 'Dry-run complete' : 'Assessment complete'} — ${f.length} findings`)
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
      hideHubParams
      title={t('serverlessSec.title', 'Serverless Security Command Center')}
      subtitle={t('serverlessSec.subtitle', 'Agentless FaaS posture — Lambda, Azure Functions, Vercel, Netlify, Cloudflare Workers — Wiz-grade attack-path synthesis')}
      badge="Serverless"
      badgeColor={ACCENT}
      icon="λ"
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
          className="relative overflow-hidden rounded-2xl border border-pink-500/30 bg-gradient-to-br from-pink-950/40 via-black/60 to-fuchsia-950/30 p-6">
          <div className="relative flex flex-wrap items-center justify-between gap-4">
            <div>
              <div className="flex items-center gap-2 mb-2 flex-wrap">
                <span className="text-[10px] font-mono px-2 py-0.5 rounded-full border border-pink-400/40 text-pink-300 bg-pink-500/10 uppercase tracking-widest">FaaS Security · λ</span>
                <span className="text-[10px] font-mono px-2 py-0.5 rounded-full border border-emerald-400/30 text-emerald-300 bg-emerald-500/10 uppercase tracking-widest">{paramCount} live parameters</span>
                <span className="text-[10px] font-mono text-[var(--text-disabled)]">MITRE T1059 · T1190</span>
              </div>
              <h1 className="text-2xl font-bold text-white tracking-tight">{engine?.label || 'Serverless Attack'}</h1>
              <p className="text-sm text-[var(--text-tertiary)] mt-1 max-w-2xl leading-relaxed">
                {t('serverlessSec.hero_desc', 'Evidence-only remote assessment: platform fingerprinting, env leaks, CORS, IaC exposure, event injection — every finding backed by a real HTTP signal.')}
              </p>
            </div>
            <Link to={`/engines/${ENGINE_ID}`} className="text-[11px] font-mono px-3 py-1.5 rounded-lg border border-[var(--border-strong)] text-[var(--text-tertiary)] hover:text-[var(--text-primary)] hover:border-[var(--border-strong)] transition-colors">Engine Detail →</Link>
          </div>
        </motion.div>

        <div className="grid grid-cols-1 xl:grid-cols-[400px_1fr] gap-6 items-start">
          <div className="xl:sticky xl:top-4 space-y-3 xl:max-h-[calc(100dvh-2rem)] xl:overflow-y-auto pr-1">
            <div className="rounded-2xl border border-pink-500/25 bg-gradient-to-b from-pink-950/30 to-black/50 p-3">
              <div className="flex items-center justify-between mb-2 px-1">
                <h2 className="text-sm font-bold text-white tracking-tight flex items-center gap-2"><span>🎛️</span> {t('serverlessSec.control', 'Serverless Control Column')}</h2>
                <button type="button" onClick={resetParams} className="text-[9px] font-mono uppercase tracking-wide px-2 py-1 rounded-md border border-[var(--border-default)] text-[var(--text-muted)] hover:text-[var(--text-secondary)] transition-colors">{t('common.reset', 'Reset')}</button>
              </div>

              <Section title={t('common.target', 'Target Binding')} icon="🎯" accent="#22d3ee">
                <label className="block space-y-1">
                  <span className="text-[10px] font-mono text-[var(--text-muted)] uppercase">{t('common.client', 'Client')}</span>
                  <select value={selectedClientId} onChange={(e) => setSelectedClientId(e.target.value)} className="w-full rounded-lg bg-[var(--bg-3)] border border-[var(--border-default)] px-3 py-1.5 text-sm text-white focus:outline-none focus:border-pink-400/40">
                    <option value="">—</option>
                    {clients.map((c) => <option key={c.id} value={c.id}>{c.name || c.id}</option>)}
                  </select>
                </label>
                <Txt label={t('common.target', 'Target')} value={target} onChange={setTarget} placeholder="https://api.example.com" />
              </Section>

              <Section title={t('serverlessSec.scope', 'Probe Scope')} icon="🧩" count={8}>
                <Toggle label="Platform Fingerprint" checked={params.probe_fingerprint} onChange={(v) => setField('probe_fingerprint', v)} hint="AWS / Azure / GCP / Vercel / Netlify / CF Workers" />
                <Toggle label="Function Discovery" checked={params.probe_functions} onChange={(v) => setField('probe_functions', v)} hint="Invocable FaaS endpoint corpus" />
                <Toggle label="IaC / Config Exposure" checked={params.probe_config} onChange={(v) => setField('probe_config', v)} hint="serverless.yml, vercel.json, template.yaml" />
                <Toggle label="Env Variable Leakage" checked={params.probe_env_leak} onChange={(v) => setField('probe_env_leak', v)} hint="Debug /config /env endpoints" />
                <Toggle label="CORS Misconfiguration" checked={params.probe_cors} onChange={(v) => setField('probe_cors', v)} hint="Function URL preflight oracle" />
                <Toggle label="Event Injection Surface" checked={params.probe_event_injection} onChange={(v) => setField('probe_event_injection', v)} hint="Safe malformed payloads → stack traces" />
                <Toggle label="Cold-Start Timing" checked={params.probe_cold_start} onChange={(v) => setField('probe_cold_start', v)} hint="Multi-sample latency differential" />
                <Toggle label="Admin Surface" checked={params.probe_admin} onChange={(v) => setField('probe_admin', v)} hint="/_admin, /api/admin unauthenticated" />
              </Section>

              <Section title={t('serverlessSec.paths', 'Path Corpora')} icon="📂" defaultOpen={false}>
                <Area label="Function Paths" value={params.function_paths} onChange={(v) => setField('function_paths', v)} placeholder={'one per line — empty = built-in defaults\n/api/\n/.netlify/functions/hello'} rows={4} />
                <Area label="Config Paths" value={params.config_paths} onChange={(v) => setField('config_paths', v)} placeholder={'serverless.yml\ntemplate.yaml\nvercel.json'} rows={3} />
                <Area label="Debug Paths" value={params.debug_paths} onChange={(v) => setField('debug_paths', v)} placeholder={'/api/env\n/api/debug\n/actuator/env'} rows={3} />
                <Txt label="Platform Filter (csv)" value={params.platform_filter} onChange={(v) => setField('platform_filter', v)} placeholder="aws_lambda,vercel,netlify" hint={PLATFORMS.map((p) => p.id).join(', ')} />
              </Section>

              <Section title={t('serverlessSec.tuning', 'Tuning & Transport')} icon="⚙" defaultOpen={false}>
                <Segmented label="Intensity" value={params.intensity} onChange={(v) => setField('intensity', v)} options={[{ value: 'light', label: 'Light' }, { value: 'normal', label: 'Normal' }, { value: 'aggressive', label: 'Deep' }]} />
                <Txt label="Timeout (ms)" value={params.timeout_ms} onChange={(v) => setField('timeout_ms', v)} />
                <Txt label="Concurrency" value={params.concurrency} onChange={(v) => setField('concurrency', v)} />
                <Txt label="Cold-Start Samples" value={params.cold_start_samples} onChange={(v) => setField('cold_start_samples', v)} />
                <Txt label="CORS Test Origin" value={params.cors_test_origin} onChange={(v) => setField('cors_test_origin', v)} />
                <Txt label="Max Requests" value={params.max_requests} onChange={(v) => setField('max_requests', v)} />
                <Txt label="Bearer Token" value={params.bearer_token} onChange={(v) => setField('bearer_token', v)} placeholder="optional" />
                <Txt label="User-Agent" value={params.user_agent} onChange={(v) => setField('user_agent', v)} placeholder="(default probe UA)" />
                <div className="space-y-1.5 pt-1">
                  <div className="flex items-center justify-between">
                    <span className="text-[10px] font-mono text-[var(--text-muted)] uppercase tracking-wide">{t('serverlessSec.extra_headers', 'Extra Headers')}</span>
                    <button type="button" onClick={addHeader}
                      className="text-[10px] font-mono px-2 py-0.5 rounded border border-[var(--border-default)] text-[var(--text-tertiary)] hover:text-pink-300 hover:border-pink-500/40 transition-colors">
                      + {t('serverlessSec.add_header', 'Add')}
                    </button>
                  </div>
                  {params.extra_headers.map((h, i) => (
                    <div key={i} className="flex items-center gap-1.5">
                      <input value={h.name} onChange={(e) => setHeader(i, 'name', e.target.value)} placeholder={t('serverlessSec.header_name', 'Header')}
                        aria-label={t('serverlessSec.header_name', 'Header')}
                        className="flex-1 min-w-0 rounded-lg bg-[var(--bg-3)] border border-[var(--border-default)] px-2 py-1 text-[11px] text-white font-mono placeholder-white/20 focus:outline-none focus:border-pink-400/40" />
                      <input value={h.value} onChange={(e) => setHeader(i, 'value', e.target.value)} placeholder={t('serverlessSec.header_value', 'Value')}
                        aria-label={t('serverlessSec.header_value', 'Value')}
                        className="flex-1 min-w-0 rounded-lg bg-[var(--bg-3)] border border-[var(--border-default)] px-2 py-1 text-[11px] text-white font-mono placeholder-white/20 focus:outline-none focus:border-pink-400/40" />
                      <button type="button" onClick={() => removeHeader(i)} aria-label={t('serverlessSec.remove_header', 'Remove header')}
                        className="shrink-0 w-6 h-6 rounded border border-[var(--border-default)] text-[var(--text-muted)] hover:text-rose-300 hover:border-rose-500/40 transition-colors">×</button>
                    </div>
                  ))}
                  {params.extra_headers.length === 0 && (
                    <p className="text-[9px] font-mono text-[var(--text-disabled)]">{t('serverlessSec.no_headers', 'No custom headers — Authorization/Bearer sent separately.')}</p>
                  )}
                </div>
              </Section>

              <Section title={t('serverlessSec.output', 'Output & Synthesis')} icon="📊" defaultOpen={false}>
                <Toggle label="Attack-Path Synthesis" checked={params.attack_path_synthesis} onChange={(v) => setField('attack_path_synthesis', v)} hint="Wiz-style toxic combinations" />
                <Toggle label="Posture Scoring" checked={params.posture_scoring} onChange={(v) => setField('posture_scoring', v)} hint="0–100 grade + A–F" />
                <Toggle label="Dry Run" checked={params.dry_run} onChange={(v) => setField('dry_run', v)} hint="Plan only — no probes" />
              </Section>

              <div className="flex gap-2 mt-3">
                <button type="button" disabled={running || !selectedClientId || !target.trim()} onClick={() => handleRun()}
                  className="flex-1 py-2.5 rounded-xl font-mono text-sm font-semibold bg-gradient-to-r from-pink-600 to-fuchsia-600 text-white disabled:opacity-40 hover:from-pink-500 hover:to-fuchsia-500 transition-all">
                  {running ? t('common.running', 'Running…') : t('serverlessSec.run', 'Run Serverless Scan')}
                </button>
                <button type="button" disabled={running || !selectedClientId || !target.trim()} onClick={() => handleRun({ dryRun: true })}
                  className="px-3 py-2.5 rounded-xl font-mono text-[11px] border border-[var(--border-strong)] text-[var(--text-tertiary)] hover:text-[var(--text-primary)] hover:border-[var(--border-strong)] disabled:opacity-40 transition-all">
                  Dry Run
                </button>
              </div>
            </div>
          </div>

          <div className="space-y-4">
            {metrics && (
              <motion.div initial={{ opacity: 0 }} animate={{ opacity: 1 }} className="rounded-2xl border border-pink-500/30 bg-[var(--bg-2)] p-4">
                <h3 className="text-sm font-mono text-pink-300 uppercase tracking-widest mb-3">Posture Score</h3>
                <div className="flex items-end gap-4">
                  <span className="text-5xl font-bold text-white">{metrics.score}<span className="text-2xl text-[var(--text-muted)]">/100</span></span>
                  <span className="text-3xl font-mono text-pink-400 mb-1">Grade {metrics.grade}</span>
                </div>
                <div className="mt-3 grid grid-cols-2 sm:grid-cols-4 gap-2 text-[10px] font-mono">
                  {[
                    ['Functions', metrics.functions_exposed],
                    ['Config leaks', metrics.config_exposed],
                    ['Env leak', metrics.env_leak ? 'YES' : 'no'],
                    ['CORS issue', metrics.cors_wildcard ? 'YES' : 'no'],
                    ['Admin open', metrics.unauthenticated_admin ? 'YES' : 'no'],
                    ['Cold start', metrics.cold_start_confirmed ? 'YES' : 'no'],
                  ].map(([k, v]) => (
                    <div key={k} className="rounded-lg bg-[var(--row-hover-bg)] border border-[var(--border-default)] px-2 py-1.5">
                      <span className="text-[var(--text-muted)] block">{k}</span>
                      <span className="text-[var(--text-secondary)]">{String(v)}</span>
                    </div>
                  ))}
                </div>
                {Array.isArray(metrics.platforms) && metrics.platforms.length > 0 && (
                  <div className="mt-2 flex flex-wrap gap-1">
                    {metrics.platforms.map((p) => <span key={p} className="text-[9px] font-mono px-2 py-0.5 rounded-full border border-pink-400/30 text-pink-300">{p}</span>)}
                  </div>
                )}
              </motion.div>
            )}

            {attackPaths.length > 0 && (
              <div className="rounded-2xl border border-red-500/30 bg-red-950/10 p-4 space-y-2">
                <h3 className="text-sm font-mono text-red-300 uppercase tracking-widest">Attack Paths ({attackPaths.length})</h3>
                {attackPaths.map((f, i) => <FindingRow key={i} f={f} />)}
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
              emptyReadyTitle={t('serverlessSec.no_findings', 'No findings yet — configure target and run scan.')}
              renderFinding={(f, i) => <FindingRow key={i} f={f} />}
            />

            <div className="rounded-2xl border border-[var(--border-default)] bg-[var(--scrim)] p-4">
              <h3 className="text-sm font-mono text-[var(--text-tertiary)] uppercase tracking-widest mb-2">{t('serverlessSec.telemetry', 'Live Telemetry')}</h3>
              <div className="h-48 overflow-y-auto font-mono text-[10px] text-emerald-400/80 space-y-0.5">
                {lines.length === 0 && <span className="text-[var(--text-disabled)]">—</span>}
                {lines.map((l, i) => <div key={i}>{l}</div>)}
              </div>
            </div>

            <div className="rounded-2xl border border-[var(--border-default)] bg-[var(--table-surface)] p-4">
              <h3 className="text-sm font-mono text-[var(--text-tertiary)] uppercase tracking-widest mb-3">{t('serverlessSec.reference', 'Attack Reference')}</h3>
              <div className="grid grid-cols-1 sm:grid-cols-2 gap-2">
                {ATTACK_REFERENCE.map((r) => {
                  const m = SEV_META[r.sev] || SEV_META.info
                  return (
                    <div key={r.id} className="rounded-lg border border-[var(--border-default)] bg-[var(--row-hover-bg)] px-3 py-2">
                      <span className={`text-[9px] font-mono uppercase ${m.text}`}>{r.sev}</span>
                      <p className="text-[11px] font-mono text-[var(--text-tertiary)] mt-0.5">{r.desc}</p>
                    </div>
                  )
                })}
              </div>
            </div>
          </div>
        </div>
      </div>
    </PageShell>
  )
}
