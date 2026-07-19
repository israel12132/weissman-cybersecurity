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
import { apiFetch } from '../utils/apiFetch'
import { useJobPoll, resolveJobFindings, extractFindingsFromJob } from '../lib/useJobPoll'
import Button from '../components/ui/Button'

const ENGINE_ID = 'pqc_scanner'

const NIST_ALGORITHMS = [
  { id: 'ML-KEM (CRYSTALS-Kyber)', type: 'KEM', status: 'final', standard: 'FIPS 203', color: '#4ade80' },
  { id: 'ML-DSA (CRYSTALS-Dilithium)', type: 'Signature', status: 'final', standard: 'FIPS 204', color: '#4ade80' },
  { id: 'SLH-DSA (SPHINCS+)', type: 'Signature', status: 'final', standard: 'FIPS 205', color: '#4ade80' },
  { id: 'FN-DSA (FALCON)', type: 'Signature', status: 'draft', standard: 'FIPS 206', color: '#f59e0b' },
  { id: 'X25519MLKEM768', type: 'Hybrid KEX', status: 'final', standard: 'RFC 9370', color: '#22d3ee' },
  { id: 'RSA-2048', type: 'Legacy KEX', status: 'quantum-vulnerable', standard: 'PKCS#1', color: '#ef4444' },
  { id: 'ECDSA P-256', type: 'Legacy Sig', status: 'quantum-vulnerable', standard: 'FIPS 186', color: '#ef4444' },
]

const FRAMEWORKS = ['cnsa_2_0', 'nist', 'bsi', 'anssi', 'custom']
const INTENSITIES = ['light', 'normal', 'aggressive']

// Full default knob surface — mirrors every parameter the backend ArsenalConfig reads.
const DEFAULT_PARAMS = {
  // Scope
  tls_ports: '443',
  ssh_ports: '22',
  sni: '',
  // Probe toggles
  check_tls_kex: true,
  check_ssh_kex: true,
  check_certificate: true,
  check_well_known: true,
  check_ct_logs: true,
  check_hndl: true,
  check_compliance: true,
  // Harvest-Now-Decrypt-Later (Mosca's inequality)
  hndl_data_lifetime_years: '10',
  hndl_migration_years: '3',
  quantum_eta_years: '10',
  // Compliance
  compliance_framework: 'cnsa_2_0',
  compliance_deadline_year: '2030',
  // Transport
  timeout_ms: '6000',
  intensity: 'normal',
}

const splitCsv = (s) => String(s || '').split(/[,\s;]+/).map((x) => x.trim()).filter(Boolean)
const numOr = (v, d) => {
  const n = Number(v)
  return Number.isFinite(n) ? n : d
}


/** Serialize the control state into the exact POST /api/command-center/scan body. */
function buildScanBody(params, clientId, target) {
  const body = {
    engine: ENGINE_ID,
    client_id: Number(clientId),
    target: (target || '').trim(),
    timeout: 300,
    check_tls_kex: !!params.check_tls_kex,
    check_ssh_kex: !!params.check_ssh_kex,
    check_certificate: !!params.check_certificate,
    check_well_known: !!params.check_well_known,
    check_ct_logs: !!params.check_ct_logs,
    check_hndl: !!params.check_hndl,
    check_compliance: !!params.check_compliance,
    hndl_data_lifetime_years: numOr(params.hndl_data_lifetime_years, 10),
    hndl_migration_years: numOr(params.hndl_migration_years, 3),
    quantum_eta_years: numOr(params.quantum_eta_years, 10),
    compliance_framework: params.compliance_framework,
    compliance_deadline_year: numOr(params.compliance_deadline_year, 2030),
    timeout_ms: numOr(params.timeout_ms, 6000),
    intensity: params.intensity,
  }
  const tp = splitCsv(params.tls_ports)
  if (tp.length) body.tls_ports = tp.join(',')
  const sp = splitCsv(params.ssh_ports)
  if (sp.length) body.ssh_ports = sp.join(',')
  if (params.sni.trim()) body.sni = params.sni.trim()
  return body
}

// ─── Reusable control primitives ─────────────────────────────────────────────

function Section({ title, icon, accent = '#10b981', count, defaultOpen = true, children }) {
  const [open, setOpen] = useState(defaultOpen)
  return (
    <div className="rounded-xl border bg-[var(--table-surface)] overflow-hidden" style={{ borderColor: `${accent}22` }}>
      <Button variant="unstyled"
        type="button"
        onClick={() => setOpen((o) => !o)}
        className="w-full flex items-center justify-between px-3 py-2.5 hover:bg-[var(--row-hover-bg)] transition-colors"
      >
        <span className="flex items-center gap-2 text-[11px] font-mono uppercase tracking-[0.18em] font-semibold" style={{ color: accent }}>
          <span>{icon}</span>
          {title}
          {count != null && <span className="text-[var(--text-disabled)] normal-case tracking-normal">· {count}</span>}
        </span>
        <span className={`text-[var(--text-muted)] text-xs transition-transform ${open ? 'rotate-90' : ''}`}>▶</span>
      </Button>
      {open && <div className="px-3 pb-3 pt-1 space-y-3 border-t border-[var(--border-subtle)]">{children}</div>}
    </div>
  )
}

function FieldRow({ label, hint, children }) {
  return (
    <label className="block space-y-1">
      <span className="text-[10px] font-mono text-[var(--text-tertiary)] uppercase tracking-wider">{label}</span>
      {children}
      {hint && <span className="block text-[9px] font-mono text-[var(--text-disabled)] leading-relaxed">{hint}</span>}
    </label>
  )
}

function TextField({ label, hint, value, onChange, placeholder, mono = true }) {
  return (
    <FieldRow label={label} hint={hint}>
      <input
        type="text"
        value={value}
        placeholder={placeholder}
        onChange={(e) => onChange(e.target.value)}
        className={`w-full bg-[var(--scrim)] border border-[var(--border-default)] rounded-lg px-2.5 py-1.5 text-xs text-[var(--text-primary)] ${mono ? 'font-mono' : ''} focus:outline-none focus:border-[#10b981]/40`}
      />
    </FieldRow>
  )
}

function NumField({ label, hint, value, onChange, min, max }) {
  return (
    <FieldRow label={label} hint={hint}>
      <input
        type="number"
        value={value}
        min={min}
        max={max}
        onChange={(e) => onChange(e.target.value)}
        className="w-full bg-[var(--scrim)] border border-[var(--border-default)] rounded-lg px-2.5 py-1.5 text-xs text-[var(--text-primary)] font-mono focus:outline-none focus:border-[#10b981]/40"
      />
    </FieldRow>
  )
}

function SelectField({ label, hint, value, onChange, options }) {
  return (
    <FieldRow label={label} hint={hint}>
      <select
        value={value}
        onChange={(e) => onChange(e.target.value)}
        className="w-full bg-[var(--scrim)] border border-[var(--border-default)] rounded-lg px-2.5 py-1.5 text-xs text-[var(--text-primary)] font-mono focus:outline-none focus:border-[#10b981]/40"
      >
        {options.map((o) => <option key={o.value} value={o.value}>{o.label}</option>)}
      </select>
    </FieldRow>
  )
}

function Toggle({ label, value, onChange }) {
  return (
    <Button variant="unstyled"
      type="button"
      onClick={() => onChange(!value)}
      className={`flex items-center justify-between w-full px-2.5 py-1.5 rounded-lg border text-[11px] font-mono transition-all ${
        value ? 'border-[#10b981]/40 bg-[#10b981]/10 text-[#10b981]' : 'border-[var(--border-default)] bg-[var(--bg-2)] text-[var(--text-muted)] hover:text-[var(--text-tertiary)]'
      }`}
    >
      <span>{label}</span>
      <span className={`w-7 h-4 rounded-full relative transition-colors ${value ? 'bg-[#10b981]/40' : 'bg-[var(--row-hover-bg)]'}`}>
        <span className={`absolute top-0.5 w-3 h-3 rounded-full bg-white transition-all ${value ? 'left-3.5' : 'left-0.5'}`} />
      </span>
    </Button>
  )
}

// ─── Result widgets ──────────────────────────────────────────────────────────

function scoreColor(score) {
  if (score >= 80) return '#4ade80'
  if (score >= 50) return '#f59e0b'
  if (score >= 25) return '#fb923c'
  return '#ef4444'
}

function ScoreGauge({ score, label }) {
  const c = scoreColor(score)
  const r = 52
  const circ = 2 * Math.PI * r
  const dash = (score / 100) * circ
  return (
    <div className="relative flex items-center justify-center w-[140px] h-[140px]">
      <svg width="140" height="140" className="-rotate-90">
        <circle cx="70" cy="70" r={r} fill="none" stroke="rgba(255,255,255,0.08)" strokeWidth="10" />
        <motion.circle
          cx="70" cy="70" r={r} fill="none" stroke={c} strokeWidth="10" strokeLinecap="round"
          strokeDasharray={`${dash} ${circ}`}
          initial={{ strokeDasharray: `0 ${circ}` }}
          animate={{ strokeDasharray: `${dash} ${circ}` }}
          transition={{ duration: 0.9, ease: 'easeOut' }}
          style={{ filter: `drop-shadow(0 0 6px ${c}80)` }}
        />
      </svg>
      <div className="absolute inset-0 flex flex-col items-center justify-center">
        <span className="text-4xl font-bold font-mono" style={{ color: c }}>{score}</span>
        <span className="text-[9px] font-mono text-[var(--text-muted)] uppercase tracking-widest">{label}</span>
      </div>
    </div>
  )
}

function PostureChip({ label, state }) {
  // state: 'good' | 'bad' | 'warn' | 'na'
  const styles = {
    good: 'text-[#4ade80] bg-[#4ade80]/10 border-[#4ade80]/30',
    bad: 'text-red-300 bg-red-950/30 border-red-500/30',
    warn: 'text-amber-300 bg-amber-950/20 border-amber-500/30',
    na: 'text-[var(--text-disabled)] bg-[var(--row-hover-bg)] border-[var(--border-default)]',
  }[state] ?? 'text-[var(--text-disabled)] bg-[var(--row-hover-bg)] border-[var(--border-default)]'
  const glyph = { good: '✓', bad: '✕', warn: '!', na: '–' }[state] ?? '–'
  return (
    <div className={`flex items-center gap-2 px-2.5 py-1.5 rounded-lg border text-[10px] font-mono ${styles}`}>
      <span className="font-bold">{glyph}</span>
      <span>{label}</span>
    </div>
  )
}

const SEV_RANK = { critical: 5, high: 4, medium: 3, low: 2, info: 1 }
const SEV_STYLE = {
  critical: 'text-red-300 border-red-500/40 bg-red-950/30',
  high: 'text-orange-300 border-orange-500/40 bg-orange-950/20',
  medium: 'text-amber-300 border-amber-500/30 bg-amber-950/15',
  low: 'text-sky-300 border-sky-500/30 bg-sky-950/15',
  info: 'text-emerald-300 border-emerald-500/30 bg-emerald-950/15',
}

function FindingCard({ f }) {
  const sev = String(f.severity || 'info').toLowerCase()
  const [open, setOpen] = useState(false)
  const ev = f.evidence || {}
  const checks = Array.isArray(ev.checks) ? ev.checks : []
  return (
    <div className={`rounded-xl border ${SEV_STYLE[sev] ?? SEV_STYLE.info} overflow-hidden`}>
      <Button variant="unstyled" type="button" onClick={() => setOpen((o) => !o)} className="w-full flex items-start gap-2 px-3 py-2 text-left hover:bg-[var(--row-hover-bg)]">
        <span className="text-[8px] font-mono uppercase tracking-widest px-1.5 py-0.5 rounded border border-current shrink-0 mt-0.5">{sev}</span>
        <span className="text-[11px] font-mono text-[var(--text-primary)] flex-1 leading-snug">{f.title || f.type}</span>
        {typeof f.confidence === 'number' && (
          <span className="text-[9px] font-mono text-[var(--text-disabled)] shrink-0">{Math.round(f.confidence * 100)}%</span>
        )}
        <span className={`text-[var(--text-disabled)] text-[10px] transition-transform ${open ? 'rotate-90' : ''}`}>▶</span>
      </Button>
      {open && (
        <div className="px-3 pb-3 pt-1 space-y-2 border-t border-[var(--border-subtle)]">
          {f.description && <p className="text-[10px] font-mono text-[var(--text-tertiary)] leading-relaxed">{f.description}</p>}
          {f.remediation && (
            <p className="text-[10px] font-mono text-[#10b981]/70 leading-relaxed"><span className="text-[var(--text-disabled)]">→ </span>{f.remediation}</p>
          )}
          {checks.length > 0 && (
            <div className="space-y-1">
              {checks.map((c, i) => (
                <div key={i} className="flex items-center gap-2 text-[9px] font-mono">
                  <span className={c.observed ? 'text-[#4ade80]' : 'text-[var(--text-disabled)]'}>{c.observed ? '●' : '○'}</span>
                  <span className="text-[var(--text-tertiary)]">{c.name}</span>
                  <span className="text-[var(--text-disabled)] truncate">{typeof c.detail === 'string' ? c.detail : JSON.stringify(c.detail)}</span>
                </div>
              ))}
            </div>
          )}
        </div>
      )}
    </div>
  )
}

export default function PqcRadar() {
  const { t } = useTranslation()
  const tt = useCallback((key, def) => t(`pages.pqcRadar.${key}`, { defaultValue: def }), [t])

  const [clients, setClients] = useState([])
  const [selectedClientId, setSelectedClientId] = useState(null)
  const { postScan } = useCommandCenterScan(selectedClientId)
  const [target, setTarget] = useState('')
  const [targetTouched, setTargetTouched] = useState(false)
  const [params, setParams] = useState(DEFAULT_PARAMS)
  useSyncHubScanParams(ENGINE_ID, params)
  const [findings, setFindings] = useState([])
  const [scanning, setScanning] = useState(false)
  const [pendingJobId, setPendingJobId] = useState(null)
  const [toast, setToast] = useState(null)

  const setParam = useCallback((k, v) => setParams((p) => ({ ...p, [k]: v })), [])

  const summary = useMemo(() => {
    if (!Array.isArray(findings) || !findings.length) return null
    return findings.find((f) => f.type === 'pqc_posture_summary') ?? null
  }, [findings])

  const detailFindings = useMemo(() => {
    if (!Array.isArray(findings)) return []
    return findings.filter((f) => f.type !== 'pqc_posture_summary')
  }, [findings])

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
  } = useWeissmanEnginePage(ENGINE_ID, detailFindings)

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

  useJobPoll(pendingJobId, {
    enabled: Boolean(pendingJobId),
    onComplete: async (job) => {
      const resolved = await resolveJobFindings(job, ENGINE_ID, selectedClientId)
      const fromJob = extractFindingsFromJob(job)
      setFindings(resolved.length ? resolved : fromJob)
      setLastUpdated(new Date().toISOString())
      if (pendingJobId) setLastJobId(pendingJobId)
      setScanning(false)
      setPendingJobId(null)
    },
  })

  useEffect(() => {
    apiFetch('/api/clients')
      .then((d) => { if (Array.isArray(d)) setClients(d) })
      .catch(() => {})
  }, [])

  // Auto-fill target from the selected client's primary domain (unless the operator edited it).
  useEffect(() => {
    if (targetTouched) return
    const client = clients.find((c) => String(c.id) === String(selectedClientId))
    setTarget(firstClientTarget(client))
  }, [selectedClientId, clients, targetTouched])

  const showToast = useCallback((sev, msg) => {
    const id = Date.now()
    setToast({ id, sev, msg })
    setTimeout(() => setToast((cur) => (cur?.id === id ? null : cur)), 5000)
  }, [])

  const handleScan = useCallback(async () => {
    if (!selectedClientId) { showToast('error', tt('select_client_first', 'Select a client first')); return }
    if (!target.trim()) { showToast('error', tt('target_required', 'A target host is required (auto-filled from the client, or enter one)')); return }
    setScanning(true)
    setFindings([])
    try {
      const { ok, data: d, status } = await postScan(buildScanBody(params, selectedClientId, target))
      if (!ok) { setScanning(false); showToast('error', d.detail || tt('scan_failed', 'Scan failed')); return }
      const jobId = d.job_id ?? ''
      showToast('info', tt('scan_queued', 'PQC scan queued: job {{jobId}}').replace('{{jobId}}', jobId))
      if (jobId) setPendingJobId(jobId)
      else setScanning(false)
    } catch (e) {
      setScanning(false)
      showToast('error', e?.message ?? tt('scan_failed', 'Scan failed'))
    }
  }, [selectedClientId, target, params, showToast, tt])

  const score = summary ? Number(summary.readiness_score ?? 0) : null
  const ev = summary?.evidence ?? {}
  const sshState = !ev.ssh_checked ? 'na' : (!ev.ssh_reachable ? 'na' : (ev.ssh_pqc_kex ? 'good' : 'bad'))

  const sortedFindings = useMemo(() => {
    return [...filteredFindings].sort(
      (a, b) => (SEV_RANK[String(b.severity).toLowerCase()] ?? 0) - (SEV_RANK[String(a.severity).toLowerCase()] ?? 0),
    )
  }, [filteredFindings])

  return (
    <PageShell
      hideHubParams
      title={tt('title', 'Post-Quantum Readiness Radar')}
      badge={tt('badge', 'CRYPTO / PQC')}
      badgeColor="#10b981"
      subtitle={tt('subtitle', 'Live PQC key-exchange negotiation · NIST FIPS 203/204/205 · CNSA 2.0')}
      actions={(
        <ShellScanActions
          onRefresh={handleRefresh}
          onExport={exportCsv}
          refreshLoading={historyLoading}
          refreshDisabled={scanning}
          exportDisabled={!sortedFindings.length}
        />
      )}
    >
      {/* Control bar */}
      <div className="flex items-end justify-between gap-3 mb-6 flex-wrap">
        <div className="flex items-end gap-3 flex-wrap">
          <label className="space-y-1">
            <span className="block text-[10px] font-mono text-[var(--text-muted)] uppercase tracking-wider">{tt('client_label', 'Client')}</span>
            <select
              value={selectedClientId ?? ''}
              onChange={(e) => { setSelectedClientId(e.target.value || null); setTargetTouched(false) }}
              className="bg-[var(--scrim)] border border-[var(--border-default)] rounded-lg px-3 py-1.5 text-xs text-[var(--text-secondary)] font-mono focus:outline-none focus:border-[#10b981]/40 min-w-[180px]"
            >
              <option value="">{tt('select_client', '— Select client —')}</option>
              {clients.map((c) => <option key={c.id} value={c.id}>{c.name}</option>)}
            </select>
          </label>
          <label className="space-y-1">
            <span className="block text-[10px] font-mono text-[var(--text-muted)] uppercase tracking-wider">{tt('target_label', 'Target host')}</span>
            <input
              type="text"
              value={target}
              placeholder={tt('target_placeholder', 'example.com or https://host:port')}
              onChange={(e) => { setTarget(e.target.value); setTargetTouched(true) }}
              className="bg-[var(--scrim)] border border-[var(--border-default)] rounded-lg px-3 py-1.5 text-xs text-[var(--text-secondary)] font-mono focus:outline-none focus:border-[#10b981]/40 min-w-[260px]"
            />
          </label>
        </div>
        <Button variant="unstyled"
          type="button"
          onClick={handleScan}
          disabled={scanning || !selectedClientId}
          className="px-5 py-2 rounded-xl font-mono text-sm border border-[#10b981]/40 text-[#10b981] bg-[#10b981]/10 hover:bg-[#10b981]/20 disabled:opacity-40 disabled:cursor-not-allowed transition-all"
        >
          {scanning ? tt('scanning', '⟳ Scanning…') : tt('run_scan', '▶ Run PQC Scan')}
        </Button>
      </div>

      {toast && (
        <div className={`fixed top-16 right-4 z-50 rounded-xl border px-4 py-3 text-sm font-mono max-w-sm shadow-2xl ${toast.sev === 'error' ? 'bg-rose-950/90 border-rose-500/40 text-rose-200' : 'bg-[var(--bg-1)] border-[#10b981]/30 text-[#10b981]'}`}>
          {toast.msg}
        </div>
      )}

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* ── Parameter control column ── */}
        <div className="space-y-3 lg:col-span-1">
          <div className="flex items-center justify-between">
            <h3 className="text-[11px] font-mono text-[var(--text-muted)] uppercase tracking-widest">{tt('advanced_params', 'Scan Parameters')}</h3>
            <Button variant="unstyled" type="button" onClick={() => setParams(DEFAULT_PARAMS)} className="text-[9px] font-mono text-[var(--text-disabled)] hover:text-[var(--text-tertiary)] underline">
              {tt('reset_defaults', 'reset')}
            </Button>
          </div>

          <Section title={tt('sec_scope', 'Scope')} icon="◎">
            <TextField label={tt('tls_ports', 'TLS ports')} hint={tt('tls_ports_hint', 'Comma-separated. PQC key-exchange is probed on each.')} value={params.tls_ports} onChange={(v) => setParam('tls_ports', v)} placeholder="443, 8443" />
            <TextField label={tt('ssh_ports', 'SSH ports')} hint={tt('ssh_ports_hint', 'KEXINIT parsed for PQC hybrid key exchange.')} value={params.ssh_ports} onChange={(v) => setParam('ssh_ports', v)} placeholder="22" />
            <TextField label={tt('sni_override', 'SNI override')} hint={tt('sni_hint', 'Defaults to the target host.')} value={params.sni} onChange={(v) => setParam('sni', v)} placeholder={tt('sni_placeholder', 'auto')} />
          </Section>

          <Section title={tt('sec_probes', 'Probes')} icon="⚡">
            <Toggle label={tt('probe_tls_kex', 'TLS PQC key exchange')} value={params.check_tls_kex} onChange={(v) => setParam('check_tls_kex', v)} />
            <Toggle label={tt('probe_ssh_kex', 'SSH PQC key exchange')} value={params.check_ssh_kex} onChange={(v) => setParam('check_ssh_kex', v)} />
            <Toggle label={tt('probe_certificate', 'Certificate crypto')} value={params.check_certificate} onChange={(v) => setParam('check_certificate', v)} />
            <Toggle label={tt('probe_well_known', 'PQC capability docs')} value={params.check_well_known} onChange={(v) => setParam('check_well_known', v)} />
            <Toggle label={tt('probe_ct_logs', 'CT-log inventory')} value={params.check_ct_logs} onChange={(v) => setParam('check_ct_logs', v)} />
            <Toggle label={tt('probe_hndl', 'Harvest-now-decrypt-later')} value={params.check_hndl} onChange={(v) => setParam('check_hndl', v)} />
            <Toggle label={tt('probe_compliance', 'Compliance mapping')} value={params.check_compliance} onChange={(v) => setParam('check_compliance', v)} />
          </Section>

          <Section title={tt('sec_hndl', 'Harvest-Now-Decrypt-Later (Mosca)')} icon="⏳" accent="#fb923c">
            <NumField label={tt('hndl_data_lifetime', 'Data shelf-life (years)')} hint={tt('hndl_data_lifetime_hint', 'X — how long the protected data must stay secret.')} value={params.hndl_data_lifetime_years} onChange={(v) => setParam('hndl_data_lifetime_years', v)} min={0} max={100} />
            <NumField label={tt('hndl_migration', 'Migration time (years)')} hint={tt('hndl_migration_hint', 'Y — time to roll out PQC across the estate.')} value={params.hndl_migration_years} onChange={(v) => setParam('hndl_migration_years', v)} min={0} max={100} />
            <NumField label={tt('quantum_eta', 'Quantum horizon (years)')} hint={tt('quantum_eta_hint', 'Z — years until a cryptographically-relevant quantum computer. Exposure when X + Y > Z.')} value={params.quantum_eta_years} onChange={(v) => setParam('quantum_eta_years', v)} min={1} max={100} />
          </Section>

          <Section title={tt('sec_compliance', 'Compliance')} icon="§" accent="#a855f7">
            <SelectField
              label={tt('compliance_framework', 'Framework')}
              value={params.compliance_framework}
              onChange={(v) => setParam('compliance_framework', v)}
              options={FRAMEWORKS.map((f) => ({ value: f, label: tt(`framework_${f}`, f.toUpperCase()) }))}
            />
            <NumField label={tt('compliance_deadline', 'Target deadline year')} value={params.compliance_deadline_year} onChange={(v) => setParam('compliance_deadline_year', v)} min={2025} max={2040} />
          </Section>

          <Section title={tt('sec_transport', 'Transport')} icon="⇄" accent="#64748b" defaultOpen={false}>
            <NumField label={tt('timeout_ms', 'Per-probe timeout (ms)')} value={params.timeout_ms} onChange={(v) => setParam('timeout_ms', v)} min={200} max={30000} />
            <SelectField
              label={tt('intensity', 'Intensity')}
              value={params.intensity}
              onChange={(v) => setParam('intensity', v)}
              options={INTENSITIES.map((i) => ({ value: i, label: tt(`intensity_${i}`, i) }))}
            />
          </Section>
        </div>

        {/* ── Results column ── */}
        <div className="space-y-6 lg:col-span-2">
          <AnimatePresence mode="wait">
            {summary ? (
              <motion.div
                key="score"
                initial={{ opacity: 0, y: 8 }}
                animate={{ opacity: 1, y: 0 }}
                className="rounded-2xl bg-[var(--bg-2)] backdrop-blur-md border border-[var(--border-default)] p-6"
              >
                <div className="flex items-center gap-6 flex-wrap">
                  <ScoreGauge score={score ?? 0} label={tt('score_label', 'READINESS')} />
                  <div className="flex-1 min-w-[240px] space-y-3">
                    <div>
                      <h3 className="text-sm font-bold text-white">{tt('readiness_score', 'Quantum-Readiness Score')}</h3>
                      <p className="text-[11px] font-mono text-[var(--text-muted)] leading-relaxed mt-1">{summary.description}</p>
                    </div>
                    <div className="grid grid-cols-2 gap-2">
                      <PostureChip label={tt('posture_tls_pqc', 'TLS PQC KEX')} state={ev.tls_pqc_kex ? 'good' : 'bad'} />
                      <PostureChip label={tt('posture_ssh_pqc', 'SSH PQC KEX')} state={sshState} />
                      <PostureChip label={tt('posture_tls13', 'TLS 1.3')} state={ev.tls13 ? 'good' : 'warn'} />
                      <PostureChip label={tt('posture_hsts', 'HSTS')} state={ev.hsts ? 'good' : 'warn'} />
                      <PostureChip label={tt('posture_hndl', 'HNDL exposed')} state={summary.hndl_exposed ? 'bad' : 'good'} />
                      <PostureChip
                        label={`${tt('hndl_gap_years', 'Mosca gap')}: ${ev.mosca_gap_years ?? '?'}y`}
                        state={(ev.mosca_gap_years ?? 0) > 0 ? 'bad' : 'good'}
                      />
                    </div>
                  </div>
                </div>

                {Array.isArray(summary.roadmap) && summary.roadmap.length > 0 && (
                  <div className="mt-5 pt-4 border-t border-[var(--border-subtle)]">
                    <h4 className="text-[10px] font-mono text-[var(--text-muted)] uppercase tracking-widest mb-2">{tt('roadmap', 'Migration Roadmap')}</h4>
                    <div className="space-y-1.5">
                      {summary.roadmap.map((s) => (
                        <div key={s.order} className="flex items-start gap-2 text-[10px] font-mono">
                          <span className={`shrink-0 mt-0.5 ${s.done ? 'text-[#4ade80]' : 'text-[var(--text-disabled)]'}`}>{s.done ? '✓' : `${s.order}.`}</span>
                          <span className={s.done ? 'text-[var(--text-tertiary)]' : 'text-[var(--text-secondary)]'}>{s.title}</span>
                          <span className="text-[var(--text-disabled)] hidden md:inline">— {s.detail}</span>
                        </div>
                      ))}
                    </div>
                  </div>
                )}
              </motion.div>
            ) : (
              <motion.div
                key="empty"
                initial={{ opacity: 0 }}
                animate={{ opacity: 1 }}
                className="rounded-2xl bg-[var(--bg-2)] backdrop-blur-md border border-[var(--border-default)] p-10 text-center"
              >
                <p className="text-[11px] font-mono text-[var(--text-disabled)]">
                  {scanning
                    ? tt('scan_running', 'Negotiating post-quantum key exchange with the target…')
                    : !selectedClientId
                      ? tt('empty_no_client', 'Select a client and run the PQC scanner to measure quantum readiness.')
                      : tt('empty_ready', 'Ready — run to test live PQC key-exchange negotiation, SSH, certificates, and HNDL exposure.')}
                </p>
              </motion.div>
            )}
          </AnimatePresence>

          <WeissmanFindingsPanel
            findings={detailFindings}
            filteredFindings={sortedFindings}
            counts={counts}
            total={detailFindings.length}
            searchQuery={searchQuery}
            onSearchChange={setSearchQuery}
            severityFilter={severityFilter}
            onSeverityChange={setSeverityFilter}
            pending={scanning && detailFindings.length === 0}
            loading={historyLoading && detailFindings.length === 0}
            lastUpdated={lastUpdated}
            jobId={pendingJobId || lastJobId}
            accent="#10b981"
            showEmptyReady={!scanning && detailFindings.length === 0 && !summary}
            emptyReadyTitle={tt('empty_ready', 'Ready — run to test live PQC key-exchange negotiation, SSH, certificates, and HNDL exposure.')}
            emptyReadyBody={tt('empty_no_client', 'Select a client and run the PQC scanner to measure quantum readiness.')}
            renderFinding={(f, i) => <FindingCard key={i} f={f} />}
          />

          {/* NIST reference */}
          <motion.section
            initial={{ opacity: 0, y: 8 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ delay: 0.05 }}
            className="rounded-2xl bg-[var(--bg-2)] backdrop-blur-md border border-[var(--border-default)] p-6 space-y-3"
          >
            <div>
              <h3 className="text-xs font-mono text-[var(--text-tertiary)] uppercase tracking-widest mb-1">{tt('nist_reference', 'NIST PQC Standard Reference')}</h3>
              <p className="text-[11px] text-[var(--text-disabled)]">{tt('nist_subtitle', 'Quantum-safe algorithms vs legacy exposure')}</p>
            </div>
            <div className="grid grid-cols-1 sm:grid-cols-2 gap-2">
              {NIST_ALGORITHMS.map((algo) => (
                <div key={algo.id} className="flex items-center justify-between gap-3 px-3 py-2 rounded-xl bg-[var(--row-hover-bg)] border border-[var(--border-subtle)]">
                  <div className="flex items-center gap-2 min-w-0">
                    <span className="w-2 h-2 rounded-full shrink-0" style={{ backgroundColor: algo.color }} />
                    <div className="min-w-0">
                      <p className="text-[11px] font-mono text-[var(--text-primary)] truncate">{algo.id}</p>
                      <p className="text-[9px] font-mono text-[var(--text-muted)]">{algo.type} · {algo.standard}</p>
                    </div>
                  </div>
                  <span className="text-[8px] font-mono px-1.5 py-0.5 rounded border uppercase tracking-widest shrink-0" style={{ color: algo.color, borderColor: `${algo.color}40` }}>
                    {algo.status === 'final' ? tt('status_final', 'final') : algo.status === 'draft' ? tt('status_draft', 'draft') : tt('status_quantum_vulnerable', 'quantum-vulnerable')}
                  </span>
                </div>
              ))}
            </div>
          </motion.section>
        </div>
      </div>
    </PageShell>
  )
}
