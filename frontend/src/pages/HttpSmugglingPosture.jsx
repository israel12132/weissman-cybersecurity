import { firstClientTarget } from '../lib/clientTarget'
import { useCommandCenterScan } from '../hooks/useCommandCenterScan'
import { useSyncHubScanParams } from '../hooks/useLaunchEngineScan'
import { useState, useEffect, useCallback, useMemo } from 'react'
import { useTranslation } from 'react-i18next'
import { motion, AnimatePresence } from 'framer-motion'
import PageShell from './PageShell'
import ShellScanActions from '../components/engine/ShellScanActions'
import WeissmanFindingsPanel from '../components/engine/WeissmanFindingsPanel'
import { useWeissmanEnginePage, applyHistoryFindings } from '../hooks/useWeissmanEnginePage'
import { apiFetch } from '../lib/apiBase'
import { useJobPoll, resolveJobFindings, uiJobStatus } from '../lib/useJobPoll'

// Command Center GUI for the `http_smuggling` engine (HTTP Request Smuggling & Desync Posture).
// Every control maps 1:1 to a real engine parameter read from the scan body via ArsenalConfig.
const ENGINE = 'http_smuggling'
const ACCENT = '#fb923c'

const TOGGLES = [
  { key: 'check_cl_te', label: 'CL.TE confusion', hint: 'Conflicting Content-Length + Transfer-Encoding (raw wire probe)', defaultVal: true },
  { key: 'check_te_cl', label: 'TE.CL confusion', hint: 'Transfer-Encoding + Content-Length conflict', defaultVal: true },
  { key: 'check_zero_cl', label: '0.CL desync', hint: 'Content-Length: 0 with trailing chunked body (PortSwigger 0.CL class)', defaultVal: true },
  { key: 'check_te_te', label: 'TE.TE dual headers', hint: 'Two Transfer-Encoding values with obfuscation', defaultVal: true },
  { key: 'check_te_obfuscation', label: 'TE obfuscation oracle', hint: 'xchunked, tab/cow/quoted/compress variants vs strict chunked baseline', defaultVal: true },
  { key: 'check_cl_anomalies', label: 'Content-Length anomalies', hint: 'Negative, duplicate, zero-with-body CL parsing', defaultVal: true },
  { key: 'check_pipeline', label: 'HTTP/1.1 pipeline', hint: 'Two pipelined requests on one connection (desync prerequisite)', defaultVal: true },
  { key: 'check_dual_response', label: 'Dual-response oracle', hint: 'Embedded second HTTP status line in one read (response-queue signal)', defaultVal: true },
  { key: 'check_response_queue', label: 'Response-queue self-oracle', hint: 'Smuggle POST + pipelined GET — status shift proves queue poisoning', defaultVal: true },
  { key: 'check_cl_cl', label: 'CL.CL duplicate Content-Length', hint: 'Two CL headers with different values — tier picks different boundary', defaultVal: true },
  { key: 'check_backend_fingerprint', label: 'Front/back-end fingerprint split', hint: 'Server/Via changes between baseline GET and smuggle POST', defaultVal: true },
  { key: 'check_timing_oracle', label: 'Timing desync oracle', hint: 'Probe stall vs baseline GET (Aggressive intensity default)', defaultVal: false },
  { key: 'check_h2c_upgrade', label: 'h2c cleartext upgrade', hint: 'Upgrade: h2c → 101 Switching Protocols (H2.TE/H2.CL class)', defaultVal: true },
  { key: 'check_chunk_extensions', label: 'Chunk extensions', hint: 'Non-standard chunk-extension parsing (;ext=…)', defaultVal: true },
  { key: 'check_client_desync', label: 'Client-side desync', hint: 'GET-with-body + HTTP/1.0 persistence quirks', defaultVal: true },
  { key: 'check_h2_downgrade', label: 'HTTP/1.1 ↔ HTTP/2 schism', hint: 'Same URL over h1-only vs h2 ALPN — protocol-boundary divergence', defaultVal: true },
  { key: 'check_fingerprint', label: 'Front-end fingerprint', hint: 'Server / Via / CDN / Alt-Svc from baseline GET', defaultVal: true },
  { key: 'check_attack_paths', label: 'Attack-path synthesis', hint: 'Wiz-style kill chains from observed desync primitives', defaultVal: true },
  { key: 'check_posture_score', label: 'Posture score', hint: '0–100 desync-resistance grade summary', defaultVal: true },
]

const CATEGORY_META = {
  smuggle_confirmed: { label: 'Confirmed Desync', icon: '☠', color: '#fb7185', order: 1 },
  attack_path: { label: 'Attack Paths', icon: '⛓', color: '#f472b6', order: 2 },
  smuggle_response_queue: { label: 'Response-Queue Oracle', icon: '⇉', color: '#dc2626', order: 3 },
  smuggle_backend_fp: { label: 'Backend Tier Split', icon: '⚌', color: '#a78bfa', order: 4 },
  smuggle_cl_cl: { label: 'CL.CL Desync', icon: '═', color: '#f97316', order: 5 },
  smuggle_dual_response: { label: 'Dual-Response Oracle', icon: '⇉', color: '#ef4444', order: 6 },
  smuggle_cl_te: { label: 'CL.TE Surface', icon: '⇄', color: '#fb923c', order: 7 },
  smuggle_te_cl: { label: 'TE.CL Surface', icon: '⇆', color: '#fb923c', order: 5 },
  smuggle_zero_cl: { label: '0.CL Desync', icon: '0', color: '#f97316', order: 6 },
  smuggle_te_te: { label: 'TE.TE Ambiguity', icon: '‖', color: '#fbbf24', order: 7 },
  smuggle_te_obfuscation: { label: 'TE Obfuscation', icon: '⌇', color: '#fbbf24', order: 8 },
  smuggle_pipeline: { label: 'Pipeline / Keep-Alive', icon: '⚡', color: '#e879f9', order: 9 },
  smuggle_timing: { label: 'Timing Oracle', icon: '⏱', color: '#a855f7', order: 10 },
  smuggle_h2c: { label: 'h2c Upgrade', icon: '2', color: '#6366f1', order: 11 },
  smuggle_chunk_ext: { label: 'Chunk Extensions', icon: '⊞', color: '#818cf8', order: 12 },
  smuggle_client_desync: { label: 'Client-Side Desync', icon: '🌐', color: '#38bdf8', order: 13 },
  smuggle_cl_anomaly: { label: 'CL Anomalies', icon: '#', color: '#c084fc', order: 14 },
  smuggle_h2_downgrade: { label: 'H2 Downgrade', icon: '↕', color: '#22d3ee', order: 15 },
  smuggle_fingerprint: { label: 'Front-End Fingerprint', icon: '🔍', color: '#94a3b8', order: 16 },
  other: { label: 'Other', icon: '•', color: '#64748b', order: 99 },
}

const SEV_STYLE = {
  critical: { text: 'text-rose-300', bd: 'border-rose-500/40', bg: 'bg-rose-500/10', dot: '#fb7185' },
  high: { text: 'text-orange-300', bd: 'border-orange-500/40', bg: 'bg-orange-500/10', dot: '#fb923c' },
  medium: { text: 'text-amber-300', bd: 'border-amber-500/40', bg: 'bg-amber-500/10', dot: '#fbbf24' },
  low: { text: 'text-sky-300', bd: 'border-sky-500/40', bg: 'bg-sky-500/10', dot: '#38bdf8' },
  info: { text: 'text-slate-300', bd: 'border-[var(--border-default)]', bg: 'bg-[var(--row-hover-bg)]', dot: '#94a3b8' },
}

function gradeColor(g) { return { A: '#34d399', B: '#a3e635', C: '#fbbf24', D: '#fb923c' }[g] || '#fb7185' }
function sevValue(s) { return { critical: 4, high: 3, medium: 2, low: 1, info: 0 }[s] ?? 0 }
function csvToArray(s) { return String(s || '').split(/[,\s]+/).map((x) => x.trim()).filter(Boolean) }
function isSummary(f) { return f && (f.category === 'posture_summary' || f.summary === true || typeof f.posture_score === 'number') }

function EvidenceView({ evidence }) {
  if (!evidence || typeof evidence !== 'object') return null
  const checks = Array.isArray(evidence.checks) ? evidence.checks : []
  const scalars = Object.entries(evidence).filter(([k]) => k !== 'checks')
  return (
    <div className="mt-2 rounded-lg bg-[var(--bg-2)] border border-[var(--border-subtle)] p-3 space-y-2">
      {scalars.length > 0 && (
        <div className="grid grid-cols-1 sm:grid-cols-2 gap-x-4 gap-y-1">
          {scalars.map(([k, v]) => (
            <div key={k} className="flex items-start gap-2 text-[11px] font-mono">
              <span className="text-[var(--text-muted)] shrink-0">{k}</span>
              <span className="text-[var(--text-secondary)] break-all">{typeof v === 'object' ? JSON.stringify(v) : String(v)}</span>
            </div>
          ))}
        </div>
      )}
      {checks.length > 0 && (
        <div className="space-y-1 pt-1 border-t border-[var(--border-subtle)]">
          {checks.map((c, i) => (
            <div key={i} className="flex items-center gap-2 text-[11px] font-mono">
              <span className={c.observed ? 'text-emerald-400' : 'text-[var(--text-disabled)]'}>{c.observed ? '✓' : '·'}</span>
              <span className="text-[var(--text-tertiary)]">{c.name}</span>
              <span className="text-[var(--text-disabled)]">—</span>
              <span className="text-[var(--text-muted)] break-all">{typeof c.detail === 'object' ? JSON.stringify(c.detail) : String(c.detail)}</span>
            </div>
          ))}
        </div>
      )}
    </div>
  )
}

function FindingCard({ f }) {
  const [open, setOpen] = useState(false)
  const sev = (f.severity || 'info').toLowerCase()
  const st = SEV_STYLE[sev] || SEV_STYLE.info
  return (
    <div className={`rounded-xl border ${st.bd} ${st.bg} p-3`}>
      <button type="button" onClick={() => setOpen((o) => !o)} className="w-full text-left flex items-start gap-3">
        <span className="mt-1 w-2 h-2 rounded-full shrink-0" style={{ backgroundColor: st.dot }} />
        <div className="flex-1 min-w-0">
          <div className="flex items-center gap-2 flex-wrap">
            <span className={`text-[10px] font-mono uppercase tracking-wider ${st.text}`}>{sev}</span>
            {f.mitre_attack && <span className="text-[10px] font-mono text-[var(--text-disabled)]">· {f.mitre_attack}</span>}
            {typeof f.confidence === 'number' && <span className="text-[10px] font-mono text-[var(--text-disabled)]">· conf {(f.confidence * 100).toFixed(0)}%</span>}
          </div>
          <div className="text-sm text-[var(--text-primary)] font-medium mt-0.5">{f.title || f.type}</div>
        </div>
        <span className="text-[var(--text-disabled)] text-xs mt-1">{open ? '▾' : '▸'}</span>
      </button>
      <AnimatePresence initial={false}>
        {open && (
          <motion.div initial={{ height: 0, opacity: 0 }} animate={{ height: 'auto', opacity: 1 }} exit={{ height: 0, opacity: 0 }} className="overflow-hidden">
            <p className="text-xs text-[var(--text-tertiary)] leading-relaxed mt-2">{f.description}</p>
            {f.remediation && (
              <div className="mt-2 rounded-lg bg-emerald-500/5 border border-emerald-500/20 p-2.5">
                <div className="text-[10px] font-mono uppercase text-emerald-400/70 mb-1">Remediation</div>
                <p className="text-[11px] text-emerald-100/80 leading-relaxed">{f.remediation}</p>
              </div>
            )}
            <EvidenceView evidence={f.evidence} />
          </motion.div>
        )}
      </AnimatePresence>
    </div>
  )
}

function Scorecard({ summary, t }) {
  if (!summary) return null
  const score = summary.posture_score ?? summary.evidence?.posture_score ?? 100
  const grade = summary.grade ?? summary.evidence?.grade ?? 'A'
  const color = gradeColor(grade)
  const worst = summary.worst_severity ?? summary.evidence?.worst_severity ?? 'info'
  const st = SEV_STYLE[worst] || SEV_STYLE.info
  const cats = summary.weak_categories || summary.evidence?.weak_categories || []
  return (
    <motion.div initial={{ opacity: 0, y: 8 }} animate={{ opacity: 1, y: 0 }} className="rounded-2xl bg-[var(--bg-2)] backdrop-blur-md border border-[var(--border-default)] p-6 mb-6">
      <div className="flex flex-col md:flex-row md:items-center gap-6">
        <div className="flex items-center gap-5">
          <div className="relative w-28 h-28 shrink-0">
            <svg viewBox="0 0 100 100" className="w-full h-full -rotate-90">
              <circle cx="50" cy="50" r="44" fill="none" stroke="rgba(255,255,255,0.08)" strokeWidth="8" />
              <circle cx="50" cy="50" r="44" fill="none" stroke={color} strokeWidth="8" strokeLinecap="round" strokeDasharray={`${(score / 100) * 276.46} 276.46`} />
            </svg>
            <div className="absolute inset-0 flex flex-col items-center justify-center">
              <span className="text-3xl font-bold" style={{ color }}>{score}</span>
              <span className="text-[10px] font-mono text-[var(--text-muted)]">/ 100</span>
            </div>
          </div>
          <div>
            <div className="text-[10px] font-mono uppercase tracking-widest text-[var(--text-muted)]">{t('pages.httpSmugglingPosture.desync_resistance', 'Desync Resistance')}</div>
            <div className="text-5xl font-black leading-none" style={{ color }}>{grade}</div>
            <div className="mt-1.5">
              <span className={`text-[10px] font-mono px-2 py-0.5 rounded-full border ${st.bd} ${st.text}`}>
                {t('pages.httpSmugglingPosture.worst', 'Worst: {{sev}}', { sev: worst })}
              </span>
            </div>
          </div>
        </div>
      </div>
      {cats.length > 0 && (
        <div className="mt-4 pt-4 border-t border-[var(--border-subtle)] flex flex-wrap items-center gap-2">
          <span className="text-[10px] font-mono text-[var(--text-muted)]">{t('pages.httpSmugglingPosture.weak_areas', 'Weak areas:')}</span>
          {cats.map((c) => (
            <span key={c} className="text-[10px] font-mono px-2 py-0.5 rounded-full bg-[var(--row-hover-bg)] border border-[var(--border-default)] text-[var(--text-tertiary)]">
              {(CATEGORY_META[c] || CATEGORY_META.other).icon} {(CATEGORY_META[c] || CATEGORY_META.other).label}
            </span>
          ))}
        </div>
      )}
    </motion.div>
  )
}

export default function HttpSmugglingPosture() {
  const { t } = useTranslation()
  const [clients, setClients] = useState([])
  const [clientId, setClientId] = useState('')
  const { postScan } = useCommandCenterScan(clientId)
  const [target, setTarget] = useState('')
  const [targetTouched, setTargetTouched] = useState(false)
  const [showParams, setShowParams] = useState(false)
  const [status, setStatus] = useState('idle')
  const [findings, setFindings] = useState([])
  const [pendingJobId, setPendingJobId] = useState(null)
  const [lastRun, setLastRun] = useState(null)
  const [toast, setToast] = useState(null)

  const detailFindings = useMemo(() => findings.filter((f) => !isSummary(f)), [findings])

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
        applyHistoryFindings(run, setFindings, { setLastUpdated, setJobId: setLastJobId })
      }
    })
  }, [refreshFromHistory, setLastUpdated, setLastJobId])

  const handleRefresh = useCallback(async () => {
    const run = await refreshFromHistory()
    applyHistoryFindings(run, setFindings, { setLastUpdated, setJobId: setLastJobId })
  }, [refreshFromHistory, setLastUpdated, setLastJobId])

  const [toggles, setToggles] = useState(() => Object.fromEntries(TOGGLES.map((tg) => [tg.key, tg.defaultVal])))
  const [intensity, setIntensity] = useState('normal')
  const [paths, setPaths] = useState('/, /api, /login, /admin')
  const [canaryPrefix, setCanaryPrefix] = useState('WZSM')
  const [timeoutMs, setTimeoutMs] = useState(8000)
  const [concurrency, setConcurrency] = useState(16)
  const [includeInfo, setIncludeInfo] = useState(true)

  useEffect(() => {
    apiFetch('/api/clients').then((r) => (r.ok ? r.json() : [])).then((d) => { if (Array.isArray(d)) setClients(d) }).catch(() => {})
  }, [])

  const selectedClient = useMemo(() => clients.find((c) => String(c.id) === String(clientId)), [clients, clientId])
  useEffect(() => { if (!targetTouched) setTarget(firstClientTarget(selectedClient)) }, [selectedClient, targetTouched])

  const showToast = useCallback((sev, msg) => {
    const id = Date.now()
    setToast({ id, sev, msg })
    setTimeout(() => setToast((x) => (x?.id === id ? null : x)), 5000)
  }, [])

  useJobPoll(pendingJobId, {
    enabled: Boolean(pendingJobId),
    onComplete: async (job) => {
      setStatus(uiJobStatus(job.status))
      setLastRun(new Date().toLocaleTimeString())
      const fs = await resolveJobFindings(job, ENGINE, clientId)
      setFindings(Array.isArray(fs) ? fs : [])
      setLastUpdated(new Date().toISOString())
      if (job?.id) setLastJobId(String(job.id))
      setPendingJobId(null)
    },
  })

  const buildBody = useCallback(() => {
    const body = {
      engine: ENGINE,
      target: target.trim(),
      ...toggles,
      intensity,
      include_info_findings: includeInfo,
      timeout_ms: Number(timeoutMs) || 8000,
      paths: csvToArray(paths),
      canary_prefix: canaryPrefix.trim() || 'WZSM',
      concurrency: Number(concurrency) || 16,
    }
    if (clientId) body.client_id = Number(clientId)
    return body
  }, [target, toggles, intensity, includeInfo, timeoutMs, paths, canaryPrefix, concurrency, clientId])

  const hubScanParams = useMemo(() => {
    const { engine, target, client_id, ...rest } = buildBody()
    return rest
  }, [buildBody])
  useSyncHubScanParams(ENGINE, hubScanParams)

  const handleRun = useCallback(async () => {
    if (!clientId) { showToast('error', t('pages.httpSmugglingPosture.select_client_first', 'Select a client first')); return }
    if (!target.trim()) { showToast('error', t('pages.httpSmugglingPosture.target_required', 'A target URL is required')); return }
    setStatus('running'); setFindings([])
    try {
      const { ok, data: d, status } = await postScan(buildBody())
      if (!ok) { setStatus('error'); showToast('error', d.detail || t('pages.httpSmugglingPosture.scan_failed', 'Scan failed')); return }
      const jobId = d.job_id ?? ''
      showToast('info', t('pages.httpSmugglingPosture.queued', 'Desync scan queued ({{jobId}})', { jobId }))
      if (jobId) setPendingJobId(jobId); else setStatus('error')
    } catch (e) {
      setStatus('error'); showToast('error', e?.message ?? t('pages.httpSmugglingPosture.scan_failed', 'Scan failed'))
    }
  }, [clientId, target, buildBody, showToast, t])

  const summary = useMemo(() => findings.find(isSummary), [findings])
  const statusColor = { idle: '#475569', running: ACCENT, completed: '#4ade80', error: '#ef4444' }[status]

  return (
    <PageShell
      hideHubParams
      title={t('pages.httpSmugglingPosture.title', 'HTTP Request Smuggling & Desync Posture')}
      badge={t('pages.httpSmugglingPosture.badge', 'HTTP DESYNC / SMUGGLING')}
      badgeColor={ACCENT}
      subtitle={t('pages.httpSmugglingPosture.subtitle', 'Raw-wire HTTP/1.1 desync arsenal: CL.TE / TE.CL / 0.CL / TE.TE, TE obfuscation oracle, dual-response & timing oracles, HTTP pipeline, h2c upgrade, chunk extensions, client-side desync, H2 downgrade schism, attack-path synthesis & 0–100 posture grade. PortSwigger + BishopFox class — evidence-only.')}
      actions={(
        <ShellScanActions
          onRefresh={handleRefresh}
          onExport={exportCsv}
          refreshLoading={historyLoading}
          refreshDisabled={status === 'running'}
          exportDisabled={!filteredFindings.length}
        />
      )}
    >
      {toast && (
        <div className={`fixed top-16 right-4 z-50 rounded-xl border px-4 py-3 text-sm font-mono max-w-sm shadow-2xl ${toast.sev === 'error' ? 'bg-rose-950/90 border-rose-500/40 text-rose-200' : 'bg-[var(--bg-1)] border-orange-500/30 text-orange-200'}`}>
          {toast.msg}
        </div>
      )}

      <div className="rounded-2xl bg-[var(--bg-2)] backdrop-blur-md border border-[var(--border-default)] p-5 mb-6">
        <div className="flex flex-wrap items-end gap-4">
          <div className="flex flex-col gap-1">
            <label className="text-[10px] font-mono uppercase tracking-wider text-[var(--text-muted)]">{t('pages.httpSmugglingPosture.client', 'Client')}</label>
            <select value={clientId} onChange={(e) => { setClientId(e.target.value); setTargetTouched(false) }}
              className="bg-[var(--scrim)] border border-[var(--border-default)] rounded-lg px-3 py-2 text-xs text-[var(--text-secondary)] font-mono focus:outline-none focus:border-orange-500/40 min-w-[180px]">
              <option value="">{t('pages.httpSmugglingPosture.select_client', '— Select client —')}</option>
              {clients.map((c) => <option key={c.id} value={c.id}>{c.name}</option>)}
            </select>
          </div>
          <div className="flex flex-col gap-1 flex-1 min-w-[220px]">
            <label className="text-[10px] font-mono uppercase tracking-wider text-[var(--text-muted)]">{t('pages.httpSmugglingPosture.target_url', 'Target URL')}</label>
            <input type="text" value={target} onChange={(e) => { setTarget(e.target.value); setTargetTouched(true) }} placeholder="https://example.com"
              className="bg-[var(--scrim)] border border-[var(--border-default)] rounded-lg px-3 py-2 text-xs text-[var(--text-secondary)] font-mono focus:outline-none focus:border-orange-500/40" />
          </div>
          <div className="flex flex-col gap-1">
            <label className="text-[10px] font-mono uppercase tracking-wider text-[var(--text-muted)]">{t('pages.httpSmugglingPosture.intensity', 'Intensity')}</label>
            <select value={intensity} onChange={(e) => setIntensity(e.target.value)}
              className="bg-[var(--scrim)] border border-[var(--border-default)] rounded-lg px-3 py-2 text-xs text-[var(--text-secondary)] font-mono focus:outline-none focus:border-orange-500/40">
              <option value="light">{t('pages.httpSmugglingPosture.intensity_light', 'Light')}</option>
              <option value="normal">{t('pages.httpSmugglingPosture.intensity_normal', 'Normal')}</option>
              <option value="aggressive">{t('pages.httpSmugglingPosture.intensity_aggressive', 'Aggressive')}</option>
            </select>
          </div>
          <div className="flex items-center gap-2">
            <span className="w-2 h-2 rounded-full" style={{ backgroundColor: statusColor, boxShadow: status === 'running' ? '0 0 6px #fb923c' : 'none' }} />
            <span className="text-[10px] font-mono text-[var(--text-muted)] uppercase">{status}</span>
          </div>
          <button type="button" onClick={handleRun} disabled={status === 'running' || !clientId}
            className="px-5 py-2 rounded-xl font-mono text-sm border border-orange-500/40 text-orange-300 bg-orange-500/10 hover:bg-orange-500/20 transition-all disabled:opacity-40 disabled:cursor-not-allowed">
            {status === 'running' ? t('pages.httpSmugglingPosture.scanning', '⟳ Scanning…') : t('pages.httpSmugglingPosture.run_scan', '▶ Run Desync Scan')}
          </button>
          <button type="button" onClick={() => setShowParams((s) => !s)}
            className="px-3 py-2 rounded-xl font-mono text-xs border border-[var(--border-default)] text-[var(--text-tertiary)] hover:text-[var(--text-secondary)] hover:border-[var(--border-strong)] transition-all">
            {showParams ? t('pages.httpSmugglingPosture.hide_params', '▾ Parameters') : t('pages.httpSmugglingPosture.show_params', '▸ Parameters')}
          </button>
        </div>

        <AnimatePresence initial={false}>
          {showParams && (
            <motion.div initial={{ height: 0, opacity: 0 }} animate={{ height: 'auto', opacity: 1 }} exit={{ height: 0, opacity: 0 }} className="overflow-hidden">
              <div className="mt-5 pt-5 border-t border-[var(--border-subtle)] grid grid-cols-1 lg:grid-cols-3 gap-6">
                <div>
                  <div className="text-[10px] font-mono uppercase tracking-wider text-[var(--text-muted)] mb-2">{t('pages.httpSmugglingPosture.probe_categories', 'Probe categories')}</div>
                  <div className="grid grid-cols-1 gap-1.5">
                    {TOGGLES.map((tg) => (
                      <label key={tg.key} title={tg.hint} className="flex items-center gap-2 text-xs font-mono text-[var(--text-secondary)] cursor-pointer">
                        <input type="checkbox" checked={!!toggles[tg.key]} onChange={(e) => setToggles((p) => ({ ...p, [tg.key]: e.target.checked }))} className="accent-orange-500" />
                        {tg.label}
                      </label>
                    ))}
                    <label className="flex items-center gap-2 text-xs font-mono text-[var(--text-secondary)] cursor-pointer mt-2">
                      <input type="checkbox" checked={includeInfo} onChange={(e) => setIncludeInfo(e.target.checked)} className="accent-orange-500" />
                      {t('pages.httpSmugglingPosture.include_info', 'Include informational findings')}
                    </label>
                  </div>
                </div>
                <div className="space-y-3">
                  <div>
                    <label className="text-[10px] font-mono uppercase tracking-wider text-[var(--text-muted)] block mb-1">{t('pages.httpSmugglingPosture.paths', 'Paths to test')}</label>
                    <input type="text" value={paths} onChange={(e) => setPaths(e.target.value)} placeholder="/, /api, /login"
                      className="w-full bg-[var(--scrim)] border border-[var(--border-default)] rounded-lg px-3 py-2 text-xs text-[var(--text-secondary)] font-mono focus:outline-none focus:border-orange-500/40" />
                  </div>
                  <div>
                    <label className="text-[10px] font-mono uppercase tracking-wider text-[var(--text-muted)] block mb-1">{t('pages.httpSmugglingPosture.canary_prefix', 'Smuggle canary prefix')}</label>
                    <input type="text" value={canaryPrefix} onChange={(e) => setCanaryPrefix(e.target.value)} placeholder="WZSM"
                      className="w-full bg-[var(--scrim)] border border-[var(--border-default)] rounded-lg px-3 py-2 text-xs text-[var(--text-secondary)] font-mono focus:outline-none focus:border-orange-500/40" />
                  </div>
                </div>
                <div>
                  <label className="text-[10px] font-mono uppercase tracking-wider text-[var(--text-muted)] block mb-1">{t('pages.httpSmugglingPosture.timeout_ms', 'Per-probe timeout (ms)')}</label>
                  <input type="number" min={500} max={30000} value={timeoutMs} onChange={(e) => setTimeoutMs(e.target.value)}
                    className="w-full bg-[var(--scrim)] border border-[var(--border-default)] rounded-lg px-3 py-2 text-xs text-[var(--text-secondary)] font-mono focus:outline-none focus:border-orange-500/40" />
                  <label className="text-[10px] font-mono uppercase tracking-wider text-[var(--text-muted)] block mb-1 mt-3">{t('pages.httpSmugglingPosture.concurrency', 'Concurrency')}</label>
                  <input type="number" min={1} max={32} value={concurrency} onChange={(e) => setConcurrency(e.target.value)}
                    className="w-full bg-[var(--scrim)] border border-[var(--border-default)] rounded-lg px-3 py-2 text-xs text-[var(--text-secondary)] font-mono focus:outline-none focus:border-orange-500/40" />
                </div>
              </div>
            </motion.div>
          )}
        </AnimatePresence>
        {lastRun && <p className="text-[10px] font-mono text-[var(--text-disabled)] mt-3">{t('pages.httpSmugglingPosture.last_completed', 'Last completed: {{time}}', { time: lastRun })}</p>}
      </div>

      {!clientId && (
        <p className="text-xs font-mono text-[var(--text-muted)] mb-6">{t('pages.httpSmugglingPosture.select_client_warning', 'Select an in-scope client and target URL to run the desync posture scan.')}</p>
      )}

      {findings.length > 0 && <Scorecard summary={summary} t={t} />}

      <WeissmanFindingsPanel
        findings={detailFindings}
        filteredFindings={filteredFindings}
        counts={counts}
        total={detailFindings.length}
        searchQuery={searchQuery}
        onSearchChange={setSearchQuery}
        severityFilter={severityFilter}
        onSeverityChange={setSeverityFilter}
        pending={status === 'running' && detailFindings.length === 0}
        loading={historyLoading && detailFindings.length === 0}
        lastUpdated={lastUpdated}
        jobId={pendingJobId || lastJobId}
        accent={ACCENT}
        showEmptyReady={status !== 'running' && detailFindings.length === 0}
        emptyReadyTitle={t('pages.httpSmugglingPosture.run_to_populate', 'Run a desync scan to assess CL.TE/TE.CL confusion, TE obfuscation, pipeline behaviour and protocol-boundary fractures.')}
        emptyReadyBody={t('pages.httpSmugglingPosture.no_findings', 'No HTTP desync indicators observed — front/back-end parsing appears consistent.')}
        renderFinding={(f, i) => <FindingCard key={i} f={f} />}
      />
    </PageShell>
  )
}
