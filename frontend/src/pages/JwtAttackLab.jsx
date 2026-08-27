import { useCommandCenterScan } from '../hooks/useCommandCenterScan'
import { useSyncHubScanParams } from '../hooks/useLaunchEngineScan'
import { useState, useEffect, useCallback, useMemo } from 'react'
import { useTranslation } from 'react-i18next'
import { motion, AnimatePresence } from 'framer-motion'
import { Search } from 'lucide-react'
import PageShell from './PageShell'
import ShellScanActions from '../components/engine/ShellScanActions'
import EmptyState from '../components/ui/EmptyState'
import { SkeletonBar, SkeletonWidgetGrid } from '../components/ui/Skeleton'
import { apiFetch } from '../utils/apiFetch'
import { useJobPoll, resolveJobFindings, extractFindingsFromJob, uiJobStatus } from '../lib/useJobPoll'
import SupremeIntelligencePanels, { extractSupremeFromFindings } from '../components/engine/SupremeIntelligencePanels'
import Button from '../components/ui/Button'
import { BoundClientScanField } from '../components/scan/ClientScanBinding'

const ACCENT = '#a855f7'

const SEVERITY_META = {
  critical: { color: '#ef4444', bg: 'bg-red-950/30', border: 'border-red-500/40', text: 'text-red-300' },
  high: { color: '#f97316', bg: 'bg-orange-950/30', border: 'border-orange-500/40', text: 'text-orange-300' },
  medium: { color: '#f59e0b', bg: 'bg-amber-950/20', border: 'border-amber-500/30', text: 'text-amber-300' },
  low: { color: '#38bdf8', bg: 'bg-sky-950/20', border: 'border-sky-500/30', text: 'text-sky-300' },
  info: { color: '#4ade80', bg: 'bg-emerald-950/20', border: 'border-emerald-500/30', text: 'text-emerald-300' },
}
const SEVERITY_ORDER = { critical: 0, high: 1, medium: 2, low: 3, info: 4 }

const ATTACK_REF_KEYS = [
  { key: 'alg_none', sev: 'critical' },
  { key: 'alg_confusion', sev: 'critical' },
  { key: 'weak_hmac', sev: 'critical' },
  { key: 'kid_injection', sev: 'high' },
  { key: 'jku_ssrf', sev: 'high' },
  { key: 'jwks_hygiene', sev: 'high' },
]

const SEV_FILTER_OPTIONS = ['all', 'critical', 'high', 'medium', 'low', 'info']

function exportFindingsCsv(findings, filenamePrefix) {
  const header = ['severity', 'title', 'type', 'description', 'remediation']
  const esc = (v) => `"${String(v ?? '').replace(/"/g, '""')}"`
  const lines = [
    header.join(','),
    ...findings.map((f) =>
      [f.severity, f.title, f.type, f.description, f.remediation].map(esc).join(','),
    ),
  ]
  const blob = new Blob([lines.join('\n')], { type: 'text/csv;charset=utf-8' })
  const url = URL.createObjectURL(blob)
  const a = document.createElement('a')
  a.href = url
  a.download = `${filenamePrefix}-${new Date().toISOString().slice(0, 10)}.csv`
  a.click()
  URL.revokeObjectURL(url)
}

function KpiStrip({ counts, total, jobId, lastUpdated, t }) {
  const sevs = ['critical', 'high', 'medium', 'low', 'info']
  return (
    <div className="rounded-2xl bg-[var(--bg-2)] backdrop-blur-md border border-[var(--border-default)] p-4 space-y-3">
      <div className="flex flex-wrap items-center justify-between gap-2">
        <p className="text-[10px] font-mono text-[var(--text-muted)] uppercase tracking-widest">
          {t('pages.jwtLab.kpi_title')}
        </p>
        <div className="flex flex-wrap items-center gap-3 text-[10px] font-mono text-[var(--text-muted)]">
          {jobId && <span>{t('pages.jwtLab.job')}: {jobId}</span>}
          {lastUpdated && (
            <span>{t('pages.jwtLab.last_updated', { time: new Date(lastUpdated).toLocaleString() })}</span>
          )}
        </div>
      </div>
      <div className="flex flex-wrap gap-2">
        <div className="px-4 py-2 rounded-xl border border-[#a855f7]/30 bg-[#a855f7]/10 text-center min-w-[80px]">
          <p className="text-xl font-bold font-mono text-[#c084fc]">{total}</p>
          <p className="text-[9px] font-mono text-[var(--text-muted)] uppercase">{t('pages.jwtLab.kpi_total')}</p>
        </div>
        {sevs.filter((s) => counts[s] > 0).map((sev) => (
          <div key={sev} className={`px-4 py-2 rounded-xl border ${SEVERITY_META[sev].border} ${SEVERITY_META[sev].bg} text-center min-w-[72px]`}>
            <p className="text-xl font-bold font-mono" style={{ color: SEVERITY_META[sev].color }}>{counts[sev]}</p>
            <p className="text-[9px] font-mono text-[var(--text-muted)] uppercase">{sev}</p>
          </div>
        ))}
      </div>
    </div>
  )
}

const DEFAULT_PARAMS = {
  sample_jwt: '',
  harvest: true,
  harvest_paths: ['/', '/login', '/api/login', '/api/auth/login', '/auth', '/api/me', '/dashboard'],
  auth_endpoints: ['/api/me', '/api/user', '/api/profile', '/profile', '/v1/me', '/api/v1/me', '/api/account', '/api/admin', '/admin'],
  jwks_paths: ['/.well-known/jwks.json', '/.well-known/openid-configuration', '/oauth/jwks', '/api/jwks', '/jwks.json'],
  jwks_url: '',
  test_alg_none: true,
  test_alg_confusion: true,
  test_weak_hmac: true,
  check_jwks: true,
  analyze_claims: true,
  require_exp: true,
  max_token_lifetime_minutes: 1440,
  min_rsa_bits: 2048,
  sensitive_claims: ['role', 'roles', 'admin', 'is_admin', 'isAdmin', 'scope', 'scopes', 'groups', 'permissions', 'authorities'],
  hmac_wordlist: [],
  oast_host: '',
  intensity: 'normal',
  timeout_ms: 6000,
  concurrency: 12,
  attack_paths: true,
  emit_agent_guidance: true,
}

const JWT_CATEGORY_AXES = [
  ['signature_integrity', 'Signature integrity'],
  ['algorithm_policy', 'Algorithm policy'],
  ['key_hygiene', 'Key hygiene'],
  ['header_injection', 'Header injection'],
  ['claim_hygiene', 'Claim hygiene'],
  ['jwks_posture', 'JWKS posture'],
  ['token_lifetime', 'Token lifetime'],
  ['harvest_surface', 'Harvest surface'],
]

// ── small controls ────────────────────────────────────────────────────────────
function Toggle({ label, hint, checked, onChange }) {
  return (
    <Button variant="unstyled" type="button" role="switch" aria-checked={checked} onClick={() => onChange(!checked)} className="w-full flex items-center justify-between gap-3 px-3 py-2 rounded-lg bg-[var(--row-hover-bg)] border border-[var(--border-subtle)] hover:bg-[var(--row-hover-bg)] transition-all text-left">
      <span className="min-w-0">
        <span className="block text-[12px] font-mono text-[var(--text-primary)] truncate">{label}</span>
        {hint && <span className="block text-[10px] font-mono text-[var(--text-muted)] truncate">{hint}</span>}
      </span>
      <span className={`shrink-0 w-9 h-5 rounded-full relative transition-colors ${checked ? 'bg-[#a855f7]/70' : 'bg-white/15'}`}>
        <span className={`absolute top-0.5 w-4 h-4 rounded-full bg-white transition-all ${checked ? 'left-[18px]' : 'left-0.5'}`} />
      </span>
    </Button>
  )
}

function Segmented({ label, value, options, onChange }) {
  return (
    <div>
      {label && <p className="text-[10px] font-mono text-[var(--text-muted)] uppercase tracking-widest mb-1.5">{label}</p>}
      <div className="flex rounded-lg bg-[var(--bg-2)] border border-[var(--border-default)] p-0.5 gap-0.5">
        {options.map((o) => (
          <Button variant="unstyled" key={o.value} type="button" onClick={() => onChange(o.value)} className={`flex-1 px-2 py-1.5 rounded-md text-[11px] font-mono transition-all ${value === o.value ? 'bg-[#a855f7]/20 text-[#c084fc] border border-[#a855f7]/40' : 'text-[var(--text-muted)] hover:text-[var(--text-secondary)] border border-transparent'}`}>{o.label}</Button>
        ))}
      </div>
    </div>
  )
}

function Slider({ label, value, min, max, step = 1, suffix = '', onChange }) {
  return (
    <div>
      <div className="flex items-center justify-between mb-1">
        <p className="text-[10px] font-mono text-[var(--text-muted)] uppercase tracking-widest">{label}</p>
        <span className="text-[11px] font-mono text-[#c084fc]">{value}{suffix}</span>
      </div>
      <input type="range" min={min} max={max} step={step} value={value} onChange={(e) => onChange(Number(e.target.value))} className="w-full accent-[#a855f7] cursor-pointer" />
    </div>
  )
}

function Field({ label, children }) {
  return (
    <label className="block">
      <span className="block text-[10px] font-mono text-[var(--text-muted)] uppercase tracking-widest mb-1">{label}</span>
      {children}
    </label>
  )
}

function ListEditor({ label, value, onChange, placeholder }) {
  return (
    <Field label={label}>
      <textarea
        value={value.join('\n')}
        onChange={(e) => onChange(e.target.value.split(/[\n,]+/).map((s) => s.trim()).filter(Boolean))}
        rows={Math.min(6, Math.max(2, value.length))}
        placeholder={placeholder}
        className="w-full bg-[var(--bg-3)] border border-[var(--border-default)] rounded-md px-2 py-1.5 text-[11px] font-mono text-[var(--text-secondary)] focus:outline-none focus:border-[#a855f7]/40 resize-y"
      />
    </Field>
  )
}

// ── client-side JWT decode for live preview ────────────────────────────────────
function b64urlDecode(s) {
  try {
    const pad = s.length % 4 === 2 ? '==' : s.length % 4 === 3 ? '=' : ''
    const std = (s + pad).replace(/-/g, '+').replace(/_/g, '/')
    return decodeURIComponent(escape(window.atob(std)))
  } catch { return null }
}
function decodeJwt(token) {
  const parts = String(token || '').trim().replace(/^Bearer\s+/i, '').split('.')
  if (parts.length !== 3) return null
  const h = b64urlDecode(parts[0])
  const p = b64urlDecode(parts[1])
  if (!h || !p) return null
  try {
    return { header: JSON.parse(h), payload: JSON.parse(p), sig: parts[2] }
  } catch { return null }
}

function EvidenceView({ evidence }) {
  if (!evidence || typeof evidence !== 'object') return null
  const { checks, ...fields } = evidence
  const entries = Object.entries(fields).filter(([, v]) => v !== null && v !== undefined && v !== '')
  return (
    <div className="mt-2 space-y-2">
      {entries.length > 0 && (
        <div className="grid grid-cols-1 sm:grid-cols-2 gap-x-4 gap-y-1">
          {entries.map(([k, v]) => (
            <div key={k} className="flex items-start justify-between gap-2 text-[10px] font-mono border-b border-[var(--border-subtle)] py-0.5">
              <span className="text-[var(--text-muted)] shrink-0">{k}</span>
              <span className="text-[var(--text-secondary)] text-right break-all">{typeof v === 'object' ? JSON.stringify(v) : String(v)}</span>
            </div>
          ))}
        </div>
      )}
      {Array.isArray(checks) && checks.length > 0 && (
        <div className="space-y-1">
          {checks.map((c, i) => (
            <div key={i} className="flex items-center gap-2 text-[10px] font-mono">
              <span className={c.observed ? 'text-emerald-400' : 'text-[var(--text-disabled)]'}>{c.observed ? '✓' : '○'}</span>
              <span className="text-[var(--text-tertiary)]">{c.name}</span>
              {c.detail !== undefined && c.detail !== '' && <span className="text-[var(--text-muted)] truncate">— {typeof c.detail === 'object' ? JSON.stringify(c.detail) : String(c.detail)}</span>}
            </div>
          ))}
        </div>
      )}
    </div>
  )
}

function FindingRow({ f, t }) {
  const [open, setOpen] = useState(false)
  const sev = (f.severity || 'info').toLowerCase()
  const meta = SEVERITY_META[sev] || SEVERITY_META.info
  const conf = typeof f.confidence === 'number' ? Math.round(f.confidence * 100) : null
  return (
    <div className={`rounded-xl border ${meta.border} ${meta.bg} overflow-hidden`}>
      <Button variant="unstyled" type="button" onClick={() => setOpen((o) => !o)} className="w-full flex items-start gap-3 px-3 py-2.5 text-left hover:bg-[var(--row-hover-bg)] transition-colors">
        <span className={`mt-0.5 text-[9px] font-mono px-1.5 py-0.5 rounded border uppercase tracking-wider shrink-0 ${meta.text} ${meta.border}`}>{sev}</span>
        <span className="min-w-0 flex-1">
          <span className="block text-[12px] font-mono text-[var(--text-primary)]">{f.title || f.type}</span>
          {!open && <span className="block text-[10px] font-mono text-[var(--text-muted)] truncate mt-0.5">{f.description}</span>}
        </span>
        {conf !== null && <span className="text-[10px] font-mono text-[var(--text-muted)] shrink-0">{conf}%</span>}
        <span className="text-[var(--text-disabled)] text-xs shrink-0">{open ? '▾' : '▸'}</span>
      </Button>
      <AnimatePresence initial={false}>
        {open && (
          <motion.div initial={{ height: 0, opacity: 0 }} animate={{ height: 'auto', opacity: 1 }} exit={{ height: 0, opacity: 0 }} className="px-3 pb-3">
            <p className="text-[11px] font-mono text-[var(--text-tertiary)] leading-relaxed">{f.description}</p>
            {f.remediation && <p className="mt-2 text-[10px] font-mono text-purple-300/80 leading-relaxed"><span className="text-[var(--text-muted)]">{t('pages.jwtLab.remediation')}: </span>{f.remediation}</p>}
            {Array.isArray(f.compliance) && f.compliance.length > 0 && (
              <div className="mt-2 flex flex-wrap gap-1">{f.compliance.map((c) => <span key={c} className="text-[9px] font-mono px-1.5 py-0.5 rounded bg-[var(--row-hover-bg)] border border-[var(--border-default)] text-[var(--text-muted)]">{c}</span>)}</div>
            )}
            <EvidenceView evidence={f.evidence} />
          </motion.div>
        )}
      </AnimatePresence>
    </div>
  )
}

export default function JwtAttackLab() {
  const { t } = useTranslation()
  const [clients, setClients] = useState([])
  const [selectedClientId, setSelectedClientId] = useState(null)
  const { postScan } = useCommandCenterScan(selectedClientId)
  const [params, setParams] = useState(DEFAULT_PARAMS)
  useSyncHubScanParams('jwt_attack', params)
  const [target, setTarget] = useState('')
  const [scanResult, setScanResult] = useState(null)
  const [scanning, setScanning] = useState(false)
  const [pendingJobId, setPendingJobId] = useState(null)
  const [jobStatus, setJobStatus] = useState(null)
  const [toast, setToast] = useState(null)
  const [showPreview, setShowPreview] = useState(false)
  const [searchQuery, setSearchQuery] = useState('')
  const [severityFilter, setSeverityFilter] = useState('all')
  const [lastUpdated, setLastUpdated] = useState(null)
  const [historyLoading, setHistoryLoading] = useState(true)

  const set = useCallback((patch) => setParams((p) => ({ ...p, ...patch })), [])

  const loadLastRun = useCallback(async () => {
    setHistoryLoading(true)
    try {
      const d = await apiFetch('/api/engines/history/jwt_attack?limit=1')
      const runs = Array.isArray(d) ? d : Array.isArray(d?.runs) ? d.runs : []
      const last = runs[0]
      if (!last) return
      const findings = Array.isArray(last.findings) ? last.findings : []
      if (findings.length || last.job_id) {
        setScanResult({ findings, job_id: last.job_id, status: last.status })
        setLastUpdated(last.completed_at || last.updated_at || last.created_at || null)
      }
    } catch {
      /* honest empty — no seeded history */
    } finally {
      setHistoryLoading(false)
    }
  }, [])

  useJobPoll(pendingJobId, {
    enabled: Boolean(pendingJobId),
    onUpdate: (job) => setJobStatus(uiJobStatus(job.status)),
    onComplete: async (job) => {
      const findings = await resolveJobFindings(job, 'jwt_attack', selectedClientId)
      const fromJob = extractFindingsFromJob(job)
      setScanResult({ findings: findings.length ? findings : fromJob, job_id: pendingJobId, status: job.status })
      setLastUpdated(new Date().toISOString())
      setScanning(false)
      setPendingJobId(null)
    },
  })

  useEffect(() => {
    // eslint-disable-next-line no-restricted-syntax -- intentional best-effort swallow
    apiFetch('/api/clients').then((d) => { if (Array.isArray(d)) setClients(d) }).catch(() => {})
    loadLastRun()
  }, [loadLastRun])

  useEffect(() => {
    if (!selectedClientId) return
    const c = clients.find((x) => String(x.id) === String(selectedClientId))
    if (!c) return
    let domain = c.primary_domain || c.domain || ''
    if (!domain && c.domains) {
      try { const arr = Array.isArray(c.domains) ? c.domains : JSON.parse(c.domains); if (Array.isArray(arr) && arr.length) domain = arr[0] } catch { /* ignore */ }
    }
    if (domain && !target) setTarget(String(domain))
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [selectedClientId, clients])

  const showToast = useCallback((sev, msg) => {
    const id = Date.now()
    setToast({ id, sev, msg })
    setTimeout(() => setToast((cur) => (cur?.id === id ? null : cur)), 5000)
  }, [])

  const decoded = useMemo(() => decodeJwt(params.sample_jwt), [params.sample_jwt])

  const requestBody = useMemo(() => {
    const body = {
      engine: 'jwt_attack',
      client_id: selectedClientId ? Number(selectedClientId) : undefined,
      target: target.trim(),
      harvest: params.harvest,
      harvest_paths: params.harvest_paths,
      auth_endpoints: params.auth_endpoints,
      jwks_paths: params.jwks_paths,
      test_alg_none: params.test_alg_none,
      test_alg_confusion: params.test_alg_confusion,
      test_weak_hmac: params.test_weak_hmac,
      check_jwks: params.check_jwks,
      analyze_claims: params.analyze_claims,
      require_exp: params.require_exp,
      max_token_lifetime_minutes: params.max_token_lifetime_minutes,
      min_rsa_bits: params.min_rsa_bits,
      sensitive_claims: params.sensitive_claims,
      hmac_wordlist: params.hmac_wordlist,
      intensity: params.intensity,
      timeout_ms: params.timeout_ms,
      concurrency: params.concurrency,
      attack_paths: params.attack_paths,
      emit_agent_guidance: params.emit_agent_guidance,
    }
    if (params.sample_jwt.trim()) body.sample_jwt = params.sample_jwt.trim()
    if (params.jwks_url.trim()) body.jwks_url = params.jwks_url.trim()
    if (params.oast_host.trim()) body.oast_host = params.oast_host.trim()
    return body
  }, [params, selectedClientId, target])

  const handleScan = useCallback(async () => {
    if (!selectedClientId) { showToast('error', t('pages.jwtLab.select_client_first')); return }
    if (!target.trim()) { showToast('error', t('pages.jwtLab.target_required')); return }
    setScanning(true); setScanResult(null); setJobStatus('queued')
    try {
      const { ok, data: d, status: _status } = await postScan(requestBody)
      if (!ok) { showToast('error', d.detail || t('pages.jwtLab.scan_failed')); setScanning(false); return }
      const jobId = d.job_id ?? ''
      showToast('info', t('pages.jwtLab.scan_queued', { jobId }))
      if (jobId) { setPendingJobId(jobId); setScanResult({ findings: [], job_id: jobId, pending: true }) } else setScanning(false)
    } catch (e) { showToast('error', e?.message ?? t('common.error')); setScanning(false) }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [selectedClientId, target, requestBody, showToast, t])

  const counts = useMemo(() => {
    const c = { critical: 0, high: 0, medium: 0, low: 0, info: 0 }
    for (const f of scanResult?.findings || []) { const s = (f.severity || 'info').toLowerCase(); if (c[s] !== undefined) c[s] += 1 }
    return c
  }, [scanResult])

  const sortedFindings = useMemo(() => {
    return [...(scanResult?.findings || [])].sort((a, b) => (SEVERITY_ORDER[(a.severity || 'info').toLowerCase()] ?? 9) - (SEVERITY_ORDER[(b.severity || 'info').toLowerCase()] ?? 9))
  }, [scanResult])

  const supremeLabels = useMemo(() => ({
    categoryScores: t('pages.jwtLab.category_scores'),
    toxicTitle: t('pages.jwtLab.toxic_title'),
    roadmapTitle: t('pages.jwtLab.roadmap_title'),
    agentTitle: t('pages.jwtLab.agent_title'),
    pathsTitle: t('pages.jwtLab.paths_title'),
  }), [t])

  const displayFindings = useMemo(() => {
    if (!scanResult?.findings) return []
    return extractSupremeFromFindings(scanResult.findings).regular
  }, [scanResult])

  const filteredDisplayFindings = useMemo(() => {
    const q = searchQuery.trim().toLowerCase()
    const sorted = [...displayFindings].sort((a, b) => (SEVERITY_ORDER[(a.severity || 'info').toLowerCase()] ?? 9) - (SEVERITY_ORDER[(b.severity || 'info').toLowerCase()] ?? 9))
    return sorted.filter((f) => {
      const sev = (f.severity || 'info').toLowerCase()
      if (severityFilter !== 'all' && sev !== severityFilter) return false
      if (!q) return true
      const hay = `${f.title || ''} ${f.type || ''} ${f.description || ''} ${f.remediation || ''}`.toLowerCase()
      return hay.includes(q)
    })
  }, [displayFindings, searchQuery, severityFilter])

  const handleExportCsv = useCallback(() => {
    if (!filteredDisplayFindings.length) return
    exportFindingsCsv(filteredDisplayFindings, 'weissman-jwt-findings')
  }, [filteredDisplayFindings])

  const shellActions = (
    <ShellScanActions
      onRefresh={loadLastRun}
      onExport={handleExportCsv}
      refreshLoading={historyLoading}
      refreshDisabled={scanning}
      exportDisabled={!filteredDisplayFindings.length}
    />
  )

  return (
    <PageShell
      hideHubParams
      title={t('pages.jwtLab.title')}
      badge={t('pages.jwtLab.badge')}
      badgeColor={ACCENT}
      subtitle={t('pages.jwtLab.subtitle')}
      actions={shellActions}
    >
      <div className="flex items-end justify-between gap-3 mb-6 flex-wrap">
        <div className="flex items-end gap-3 flex-wrap">
          <Field label={t('pages.jwtLab.client_label')}>
            <BoundClientScanField
              clients={clients}
              selectedClientId={selectedClientId ?? ''}
              onChange={(id) => setSelectedClientId(id || null)}
              emptyLabel={t('pages.jwtLab.select_client')}
            />
          </Field>
          <Field label={t('pages.jwtLab.target_label')}>
            <input value={target} onChange={(e) => setTarget(e.target.value)} placeholder="https://api.example.com" className="bg-[var(--scrim)] border border-[var(--border-default)] rounded-lg px-3 py-2 text-xs text-[var(--text-secondary)] font-mono focus:outline-none focus:border-[#a855f7]/40 min-w-[240px]" />
          </Field>
        </div>
        <div className="flex items-center gap-2">
          {jobStatus && scanning && <span className="text-[10px] font-mono text-[var(--text-muted)] uppercase tracking-widest">{jobStatus}</span>}
          <Button variant="unstyled" type="button" onClick={() => { setParams(DEFAULT_PARAMS); showToast('info', t('pages.jwtLab.reset_done')) }} className="px-3 py-2 rounded-xl font-mono text-xs border border-[var(--border-default)] text-[var(--text-tertiary)] hover:text-[var(--text-secondary)] hover:bg-[var(--row-hover-bg)] transition-all">{t('pages.jwtLab.reset')}</Button>
          <Button variant="unstyled" type="button" onClick={handleScan} disabled={scanning || !selectedClientId} className="px-5 py-2 rounded-xl font-mono text-sm border border-[#a855f7]/40 text-[#c084fc] bg-[#a855f7]/10 hover:bg-[#a855f7]/20 disabled:opacity-40 disabled:cursor-not-allowed transition-all">{scanning ? t('pages.jwtLab.scanning') : t('pages.jwtLab.run_scan')}</Button>
        </div>
      </div>

      {toast && (
        <div className={`fixed top-16 right-4 z-50 rounded-xl border px-4 py-3 text-sm font-mono max-w-sm shadow-2xl ${toast.sev === 'error' ? 'bg-rose-950/90 border-rose-500/40 text-rose-200' : 'bg-[var(--bg-1)] border-[#a855f7]/30 text-[#c084fc]'}`}>{toast.msg}</div>
      )}

      <div className="grid grid-cols-1 xl:grid-cols-12 gap-6">
        {/* Control panel */}
        <motion.aside initial={{ opacity: 0, x: -8 }} animate={{ opacity: 1, x: 0 }} className="xl:col-span-4 space-y-5 rounded-2xl bg-[var(--bg-2)] backdrop-blur-md border border-[var(--border-default)] p-5 self-start">
          <div className="flex items-center justify-between">
            <h3 className="text-xs font-mono text-[var(--text-tertiary)] uppercase tracking-widest">{t('pages.jwtLab.control_panel')}</h3>
            <Button variant="unstyled" type="button" onClick={() => setShowPreview((s) => !s)} className="text-[10px] font-mono text-[var(--text-muted)] hover:text-[#c084fc]">{showPreview ? t('pages.jwtLab.hide_json') : t('pages.jwtLab.show_json')}</Button>
          </div>

          <Field label={t('pages.jwtLab.sample_jwt')}>
            <textarea value={params.sample_jwt} onChange={(e) => set({ sample_jwt: e.target.value })} rows={3} placeholder="eyJhbGciOi..." className="w-full bg-[var(--bg-3)] border border-[var(--border-default)] rounded-md px-2 py-1.5 text-[10px] font-mono text-[var(--text-secondary)] focus:outline-none focus:border-[#a855f7]/40 resize-y break-all" />
          </Field>
          {decoded && (
            <div className="rounded-lg border border-[#a855f7]/20 bg-[#a855f7]/5 p-2 space-y-1">
              <p className="text-[9px] font-mono text-[var(--text-muted)] uppercase tracking-widest">{t('pages.jwtLab.decoded')}</p>
              <pre className="text-[9px] font-mono text-emerald-300/80 overflow-x-auto">{JSON.stringify(decoded.header)}</pre>
              <pre className="text-[9px] font-mono text-sky-300/80 overflow-x-auto max-h-24">{JSON.stringify(decoded.payload, null, 1)}</pre>
            </div>
          )}

          <div className="space-y-2">
            <p className="text-[10px] font-mono text-[var(--text-muted)] uppercase tracking-widest">{t('pages.jwtLab.section_attacks')}</p>
            <Toggle label={t('pages.jwtLab.test_alg_none')} hint={t('pages.jwtLab.test_alg_none_hint')} checked={params.test_alg_none} onChange={(v) => set({ test_alg_none: v })} />
            <Toggle label={t('pages.jwtLab.test_alg_confusion')} hint={t('pages.jwtLab.test_alg_confusion_hint')} checked={params.test_alg_confusion} onChange={(v) => set({ test_alg_confusion: v })} />
            <Toggle label={t('pages.jwtLab.test_weak_hmac')} hint={t('pages.jwtLab.test_weak_hmac_hint')} checked={params.test_weak_hmac} onChange={(v) => set({ test_weak_hmac: v })} />
            <Toggle label={t('pages.jwtLab.check_jwks')} hint={t('pages.jwtLab.check_jwks_hint')} checked={params.check_jwks} onChange={(v) => set({ check_jwks: v })} />
            <Toggle label={t('pages.jwtLab.harvest')} hint={t('pages.jwtLab.harvest_hint')} checked={params.harvest} onChange={(v) => set({ harvest: v })} />
            <Toggle label={t('pages.jwtLab.analyze_claims')} checked={params.analyze_claims} onChange={(v) => set({ analyze_claims: v })} />
            <Toggle label={t('pages.jwtLab.require_exp')} checked={params.require_exp} onChange={(v) => set({ require_exp: v })} />
            <Toggle label={t('pages.jwtLab.attack_paths')} hint={t('pages.jwtLab.attack_paths_hint')} checked={params.attack_paths} onChange={(v) => set({ attack_paths: v })} />
            <Toggle label={t('pages.jwtLab.emit_agent_guidance')} checked={params.emit_agent_guidance} onChange={(v) => set({ emit_agent_guidance: v })} />
          </div>

          <ListEditor label={t('pages.jwtLab.auth_endpoints')} value={params.auth_endpoints} onChange={(v) => set({ auth_endpoints: v })} placeholder="/api/me" />
          <ListEditor label={t('pages.jwtLab.harvest_paths')} value={params.harvest_paths} onChange={(v) => set({ harvest_paths: v })} placeholder="/login" />
          <ListEditor label={t('pages.jwtLab.jwks_paths')} value={params.jwks_paths} onChange={(v) => set({ jwks_paths: v })} placeholder="/.well-known/jwks.json" />
          <Field label={t('pages.jwtLab.jwks_url')}>
            <input value={params.jwks_url} onChange={(e) => set({ jwks_url: e.target.value })} placeholder="https://idp.example.com/jwks.json" className="w-full bg-[var(--bg-3)] border border-[var(--border-default)] rounded-md px-2 py-1.5 text-[11px] font-mono text-[var(--text-secondary)] focus:outline-none focus:border-[#a855f7]/40" />
          </Field>
          <ListEditor label={t('pages.jwtLab.hmac_wordlist')} value={params.hmac_wordlist} onChange={(v) => set({ hmac_wordlist: v })} placeholder="company-name-2024" />
          <ListEditor label={t('pages.jwtLab.sensitive_claims')} value={params.sensitive_claims} onChange={(v) => set({ sensitive_claims: v })} placeholder="role" />

          <div className="space-y-3">
            <Segmented label={t('pages.jwtLab.intensity')} value={params.intensity} options={[{ value: 'light', label: t('pages.jwtLab.intensity_light') }, { value: 'normal', label: t('pages.jwtLab.intensity_normal') }, { value: 'aggressive', label: t('pages.jwtLab.intensity_aggressive') }]} onChange={(v) => set({ intensity: v })} />
            <Slider label={t('pages.jwtLab.timeout_ms')} value={params.timeout_ms} min={1000} max={20000} step={500} suffix="ms" onChange={(v) => set({ timeout_ms: v })} />
            <Slider label={t('pages.jwtLab.concurrency')} value={params.concurrency} min={1} max={32} step={1} onChange={(v) => set({ concurrency: v })} />
            <Slider label={t('pages.jwtLab.max_lifetime')} value={params.max_token_lifetime_minutes} min={5} max={10080} step={5} suffix="m" onChange={(v) => set({ max_token_lifetime_minutes: v })} />
            <div className="grid grid-cols-2 gap-3">
              <Field label={t('pages.jwtLab.min_rsa_bits')}>
                <select value={params.min_rsa_bits} onChange={(e) => set({ min_rsa_bits: Number(e.target.value) })} className="w-full bg-[var(--bg-3)] border border-[var(--border-default)] rounded-md px-2 py-1.5 text-[11px] font-mono text-[var(--text-secondary)] focus:outline-none focus:border-[#a855f7]/40">{[1024, 2048, 3072, 4096].map((b) => <option key={b} value={b}>{b}</option>)}</select>
              </Field>
              <Field label={t('pages.jwtLab.oast_host')}>
                <input value={params.oast_host} onChange={(e) => set({ oast_host: e.target.value })} placeholder="oast.example" className="w-full bg-[var(--bg-3)] border border-[var(--border-default)] rounded-md px-2 py-1.5 text-[11px] font-mono text-[var(--text-secondary)] focus:outline-none focus:border-[#a855f7]/40" />
              </Field>
            </div>
          </div>

          {showPreview && <pre className="text-[9px] font-mono text-[var(--text-tertiary)] bg-[var(--scrim)] border border-[var(--border-default)] rounded-lg p-3 overflow-x-auto max-h-60">{JSON.stringify(requestBody, null, 2)}</pre>}
        </motion.aside>

        {/* Results */}
        <motion.section initial={{ opacity: 0, y: 8 }} animate={{ opacity: 1, y: 0 }} transition={{ delay: 0.05 }} className="xl:col-span-8 space-y-6">
          {historyLoading && !scanResult && (
            <div className="rounded-2xl bg-[var(--bg-2)] backdrop-blur-md border border-[var(--border-default)] p-6 space-y-4">
              <SkeletonBar className="h-4 w-40" />
              <SkeletonWidgetGrid count={4} />
            </div>
          )}

          {scanResult && !scanResult.pending && (
            <KpiStrip
              counts={counts}
              total={sortedFindings.length}
              jobId={scanResult.job_id}
              lastUpdated={lastUpdated}
              t={t}
            />
          )}

          {scanResult?.pending && (
            <div className="rounded-2xl bg-[var(--bg-2)] backdrop-blur-md border border-[var(--border-default)] p-6 space-y-4">
              <p className="text-[11px] font-mono text-[#c084fc] animate-pulse">{t('pages.jwtLab.scanning_live')}</p>
              <p className="text-[10px] font-mono text-[var(--text-disabled)]">{t('pages.jwtLab.job')} {scanResult.job_id}</p>
              <SkeletonWidgetGrid count={3} />
            </div>
          )}

          {scanResult && !scanResult.pending && (
            <>
              <SupremeIntelligencePanels
                findings={scanResult.findings}
                labels={supremeLabels}
                categoryAxes={JWT_CATEGORY_AXES}
              />
            <div className="rounded-2xl bg-[var(--bg-2)] backdrop-blur-md border border-[var(--border-default)] p-5 space-y-4">
              <div className="flex flex-col sm:flex-row sm:items-center gap-3 justify-between">
                <h3 className="text-xs font-mono text-[var(--text-tertiary)] uppercase tracking-widest">
                  {t('pages.jwtLab.findings')} ({filteredDisplayFindings.length}/{displayFindings.length})
                </h3>
                <div className="flex flex-wrap items-center gap-2">
                  <div className="relative">
                    <Search className="absolute left-2.5 top-1/2 -translate-y-1/2 w-3.5 h-3.5 text-[var(--text-disabled)]" />
                    <input
                      type="search"
                      value={searchQuery}
                      onChange={(e) => setSearchQuery(e.target.value)}
                      aria-label={t('pages.jwtLab.search_placeholder')}
                      placeholder={t('pages.jwtLab.search_placeholder')}
                      className="pl-8 pr-3 py-1.5 rounded-lg bg-[var(--bg-3)] border border-[var(--border-default)] text-[11px] font-mono text-[var(--text-secondary)] placeholder-white/25 focus:outline-none focus:border-[#a855f7]/40 min-w-[200px]"
                    />
                  </div>
                  <div className="flex gap-1 flex-wrap">
                    {SEV_FILTER_OPTIONS.map((s) => (
                      <Button variant="unstyled"
                        key={s}
                        type="button"
                        onClick={() => setSeverityFilter(s)}
                        className={`text-[9px] font-mono px-2 py-0.5 rounded border uppercase ${severityFilter === s ? 'border-[#a855f7]/50 text-[#c084fc] bg-[#a855f7]/10' : 'border-[var(--border-default)] text-[var(--text-muted)] hover:text-[var(--text-tertiary)]'}`}
                      >
                        {s === 'all' ? t('pages.jwtLab.filter_all') : s}
                      </Button>
                    ))}
                  </div>
                </div>
              </div>
              {displayFindings.length === 0 ? (
                <EmptyState
                  title={t('pages.jwtLab.no_findings_title')}
                  body={t('pages.jwtLab.no_findings')}
                />
              ) : filteredDisplayFindings.length === 0 ? (
                <EmptyState
                  title={t('pages.jwtLab.empty_filtered_title')}
                  body={t('pages.jwtLab.empty_filtered')}
                />
              ) : (
                <div className="space-y-2 max-h-[520px] overflow-auto pr-1">
                  {filteredDisplayFindings.map((f, i) => <FindingRow key={`${f.title}-${i}`} f={f} t={t} />)}
                </div>
              )}
            </div>
            </>
          )}

          {!scanResult && !historyLoading && (
            <EmptyState
              title={!selectedClientId ? t('pages.jwtLab.empty_no_client_title') : t('pages.jwtLab.empty_ready_title')}
              body={!selectedClientId ? t('pages.jwtLab.empty_no_client') : t('pages.jwtLab.empty_ready')}
            />
          )}

          <div className="rounded-2xl bg-[var(--bg-2)] backdrop-blur-md border border-[var(--border-default)] p-5 space-y-3">
            <h3 className="text-xs font-mono text-[var(--text-tertiary)] uppercase tracking-widest">{t('pages.jwtLab.attack_reference')}</h3>
            <div className="grid grid-cols-1 sm:grid-cols-2 gap-2">
              {ATTACK_REF_KEYS.map((a) => (
                <div key={a.key} className="flex items-center justify-between gap-3 px-3 py-2 rounded-lg bg-[var(--row-hover-bg)] border border-[var(--border-subtle)]">
                  <div className="min-w-0">
                    <p className="text-[12px] font-mono text-[var(--text-primary)] truncate">{t(`pages.jwtLab.attack_ref.${a.key}.id`)}</p>
                    <p className="text-[9px] font-mono text-[var(--text-muted)]">{t(`pages.jwtLab.attack_ref.${a.key}.desc`)}</p>
                  </div>
                  <span className={`text-[9px] font-mono px-2 py-0.5 rounded border uppercase tracking-widest shrink-0 ${SEVERITY_META[a.sev].text} ${SEVERITY_META[a.sev].border}`}>{a.sev}</span>
                </div>
              ))}
            </div>
          </div>
        </motion.section>
      </div>
    </PageShell>
  )
}
