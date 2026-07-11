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

const ENGINE = 'mtls_grpc'
const ACCENT = '#8b5cf6'

const PROBE_TOGGLES = [
  { key: 'check_tls_cert', label: 'TLS certificate forensics', hint: 'Expiry, SAN, key strength, signature algorithm', defaultVal: true },
  { key: 'check_tls_session', label: 'TLS session matrix', hint: 'Multi-port handshakes, ALPN h2, TLS 1.3', defaultVal: true },
  { key: 'check_weak_ciphers', label: 'Weak cipher matrix', hint: 'RC4, 3DES, EXPORT, NULL, static-RSA (live forced handshakes)', defaultVal: true },
  { key: 'check_legacy_tls', label: 'Legacy TLS 1.0/1.1', hint: 'Deprecated protocol downgrade surface', defaultVal: true },
  { key: 'check_ocsp', label: 'OCSP stapling', hint: 'status_request extension in TLS handshake', defaultVal: true },
  { key: 'check_mtls', label: 'mTLS enforcement', hint: 'Anonymous TLS vs client-cert required', defaultVal: true },
  { key: 'check_sni_policy', label: 'SNI virtual-host policy', hint: 'Wrong-SNI handshake acceptance', defaultVal: true },
  { key: 'check_cert_consistency', label: 'Cert fingerprint matrix', hint: 'SHA-256 consistency across ports', defaultVal: true },
  { key: 'check_grpc_reflection', label: 'gRPC reflection / health', hint: 'Real gRPC wire frames on HTTP/2', defaultVal: true },
  { key: 'check_grpc_web', label: 'gRPC-Web / Connect-RPC', hint: 'Browser-reachable RPC surfaces', defaultVal: true },
  { key: 'check_headers', label: 'Security headers & cookies', hint: 'HSTS, CSP, clickjacking, cookie flags', defaultVal: true },
  { key: 'check_cross_origin', label: 'Cross-origin isolation', hint: 'COOP / COEP / CORP', defaultVal: true },
  { key: 'check_api_hardening', label: 'API hardening', hint: 'HTTP TRACE + permissive CORS oracle', defaultVal: true },
  { key: 'check_h2c', label: 'Cleartext h2c upgrade', hint: 'Upgrade: h2c on plain HTTP', defaultVal: true },
  { key: 'check_http3', label: 'HTTP/3 readiness', hint: 'ALPN h3 + Alt-Svc (Aggressive intensity)', defaultVal: false },
  { key: 'check_redirect', label: 'HTTP→HTTPS upgrade', hint: 'Plain HTTP redirect behaviour', defaultVal: true },
  { key: 'check_http2', label: 'HTTP/2 ALPN', hint: 'h2 negotiation on HTTPS', defaultVal: true },
  { key: 'check_dane', label: 'DANE / TLSA', hint: 'DNS certificate pinning (RFC 6698)', defaultVal: true },
  { key: 'check_caa', label: 'DNS CAA policy', hint: 'CA issuance restriction records', defaultVal: true },
  { key: 'check_ct', label: 'Certificate Transparency', hint: 'crt.sh inventory + CAA cross-check', defaultVal: true },
  { key: 'check_security_txt', label: 'security.txt', hint: 'RFC 9116 coordinated disclosure', defaultVal: true },
  { key: 'check_hsts_preload', label: 'HSTS preload readiness', hint: 'preload token eligibility', defaultVal: true },
  { key: 'check_chain_trust', label: 'Chain trust (system CAs)', hint: 'OpenSSL verify_result against trust store', defaultVal: true },
  { key: 'check_redirect_chain', label: 'Redirect chain audit', hint: 'Detect cleartext hops in HTTP→HTTPS chain', defaultVal: true },
  { key: 'check_grpc_h2c', label: 'gRPC h2c preface', hint: 'PRI * HTTP/2.0 on gRPC ports without TLS', defaultVal: true },
  { key: 'check_websocket', label: 'WebSocket upgrade', hint: '101 Switching Protocols on HTTPS origin', defaultVal: true },
  { key: 'check_cache_policy', label: 'Cache-Control policy', hint: 'Public cacheable API responses', defaultVal: true },
  { key: 'emit_coverage_manifest', label: 'Coverage manifest', hint: 'Audit trail of every executed probe module', defaultVal: true },
  { key: 'check_mixed_passive', label: 'Mixed passive content', hint: 'HTTP subresources on HTTPS pages', defaultVal: true },
  { key: 'check_must_staple', label: 'OCSP Must-Staple', hint: 'TLS Feature extension + stapling correlation', defaultVal: true },
  { key: 'check_mesh_fingerprint', label: 'Mesh/proxy fingerprint', hint: 'Envoy, Istio, Traefik, Kong headers', defaultVal: true },
  { key: 'check_tls_compression', label: 'TLS compression (CRIME)', hint: 'Live handshake compression negotiation', defaultVal: true },
  { key: 'check_reporting_headers', label: 'NEL / Report-To', hint: 'Browser TLS incident reporting', defaultVal: true },
  { key: 'check_upgrade_insecure_requests', label: 'Upgrade-Insecure-Requests', hint: 'HTTP upgrade oracle with browser header', defaultVal: true },
  { key: 'attack_path_synthesis', label: 'Attack-path synthesis', hint: 'Wiz-style MITM / gRPC kill chains', defaultVal: true },
  { key: 'posture_scoring', label: 'Posture score', hint: '0–100 transport-security grade', defaultVal: true },
]

const CATEGORY_META = {
  posture_score: { label: 'Posture Score', icon: '◈', color: ACCENT, order: 0 },
  attack_path: { label: 'Attack Paths', icon: '⛓', color: '#f472b6', order: 1 },
  tls_certificate: { label: 'TLS Certificate', icon: '🔏', color: '#a78bfa', order: 2 },
  weak_cipher: { label: 'Weak Ciphers', icon: '⚠', color: '#ef4444', order: 3 },
  legacy_tls: { label: 'Legacy TLS', icon: '↓', color: '#f97316', order: 4 },
  mtls_enforcement: { label: 'mTLS', icon: '⇄', color: '#818cf8', order: 5 },
  grpc_reflection: { label: 'gRPC Reflection', icon: '◎', color: '#fb7185', order: 6 },
  grpc_h2c: { label: 'gRPC h2c', icon: '2', color: '#dc2626', order: 7 },
  chain_trust: { label: 'Chain Trust', icon: '⛓', color: '#f87171', order: 8 },
  redirect_chain: { label: 'Redirect Chain', icon: '↪', color: '#fb923c', order: 9 },
  ct_shadow_hosts: { label: 'CT Shadow Hosts', icon: '👁', color: '#eab308', order: 10 },
  coverage_manifest: { label: 'Coverage Manifest', icon: '✓', color: ACCENT, order: 11 },
  grpc_web: { label: 'gRPC-Web / Connect', icon: '🌐', color: '#c084fc', order: 12 },
  plaintext_grpc: { label: 'Plaintext gRPC', icon: '☠', color: '#dc2626', order: 8 },
  hsts: { label: 'HSTS', icon: 'H', color: '#34d399', order: 9 },
  h2c_upgrade: { label: 'h2c Upgrade', icon: '2', color: '#6366f1', order: 10 },
  http3: { label: 'HTTP/3', icon: '3', color: '#22d3ee', order: 11 },
  cors: { label: 'CORS', icon: '↔', color: '#fbbf24', order: 12 },
  http_trace: { label: 'HTTP TRACE', icon: 'T', color: '#fb923c', order: 13 },
  dns_caa: { label: 'DNS CAA', icon: 'C', color: '#94a3b8', order: 14 },
  certificate_transparency: { label: 'CT Logs', icon: 'CT', color: '#64748b', order: 15 },
  ct_caa_violation: { label: 'CT vs CAA', icon: '!', color: '#f87171', order: 16 },
  dane: { label: 'DANE/TLSA', icon: 'D', color: '#38bdf8', order: 17 },
  other: { label: 'Other', icon: '•', color: '#475569', order: 99 },
}

const SEV_STYLE = {
  critical: { text: 'text-rose-300', bd: 'border-rose-500/40', bg: 'bg-rose-500/10' },
  high: { text: 'text-orange-300', bd: 'border-orange-500/40', bg: 'bg-orange-500/10' },
  medium: { text: 'text-amber-300', bd: 'border-amber-500/40', bg: 'bg-amber-500/10' },
  low: { text: 'text-sky-300', bd: 'border-sky-500/40', bg: 'bg-sky-500/10' },
  info: { text: 'text-[var(--text-secondary)]', bd: 'border-[var(--border-default)]', bg: 'bg-[var(--row-hover-bg)]' },
}

function gradeColor(g) {
  return { A: '#34d399', B: '#a3e635', C: '#fbbf24', D: '#fb923c', F: '#ef4444' }[g] || '#94a3b8'
}

function CategoryBreakdown({ findings }) {
  const groups = useMemo(() => {
    const counts = new Map()
    for (const f of findings) {
      const key = CATEGORY_META[f?.category] ? f.category : 'other'
      counts.set(key, (counts.get(key) || 0) + 1)
    }
    return [...counts.entries()]
      .map(([key, count]) => ({ key, count, meta: CATEGORY_META[key] || CATEGORY_META.other }))
      .sort((a, b) => a.meta.order - b.meta.order)
  }, [findings])

  if (!groups.length) return null
  return (
    <div className="flex flex-wrap gap-2">
      {groups.map(({ key, count, meta }) => (
        <span
          key={key}
          className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded-lg text-[11px] font-mono border"
          style={{ color: meta.color, borderColor: `${meta.color}33`, background: `${meta.color}0f` }}
        >
          <span aria-hidden="true">{meta.icon}</span>
          {meta.label}
          <span className="px-1.5 py-0.5 rounded bg-[var(--scrim)] text-[var(--text-secondary)]">{count}</span>
        </span>
      ))}
    </div>
  )
}


function isSummary(f) {
  return f?.category === 'posture_score' || (typeof f?.title === 'string' && f.title.includes('Transport Security Posture'))
}

function extractScore(findings) {
  const s = findings.find(isSummary)
  return s?.evidence?.score ?? s?.score ?? null
}

function extractGrade(findings) {
  const s = findings.find(isSummary)
  return s?.evidence?.grade ?? s?.grade ?? null
}

function EvidenceView({ evidence }) {
  if (!evidence || typeof evidence !== 'object') return null
  const entries = Object.entries(evidence).filter(([k]) => k !== 'checks')
  if (!entries.length) return null
  return (
    <div className="mt-2 rounded-lg bg-[var(--bg-2)] border border-[var(--border-subtle)] p-3">
      <div className="grid grid-cols-1 sm:grid-cols-2 gap-x-4 gap-y-1">
        {entries.map(([k, v]) => (
          <div key={k} className="text-[10px] font-mono text-[var(--text-muted)] truncate">
            <span className="text-[var(--text-disabled)]">{k}: </span>
            {typeof v === 'object' ? JSON.stringify(v).slice(0, 120) : String(v)}
          </div>
        ))}
      </div>
    </div>
  )
}

function FindingCard({ f }) {
  const sev = (f.severity || 'info').toLowerCase()
  const st = SEV_STYLE[sev] || SEV_STYLE.info
  return (
    <div className={`rounded-xl border p-4 ${st.bd} ${st.bg}`}>
      <div className="flex items-start justify-between gap-3">
        <div className="min-w-0">
          <div className={`text-sm font-mono font-medium ${st.text}`}>{f.title || f.type}</div>
          {f.mitre_attack && <div className="text-[10px] font-mono text-[var(--text-disabled)] mt-0.5">MITRE {f.mitre_attack}</div>}
        </div>
        <span className={`shrink-0 text-[10px] font-mono uppercase px-2 py-0.5 rounded ${st.text}`}>{sev}</span>
      </div>
      {f.description && <p className="text-xs font-mono text-[var(--text-tertiary)] mt-2 leading-relaxed">{f.description}</p>}
      <EvidenceView evidence={f.evidence} />
    </div>
  )
}

function extractDimensions(findings) {
  const s = findings.find(isSummary)
  return s?.evidence?.dimension_scores || null
}

const DIM_LABELS = {
  tls_crypto: 'TLS / Crypto',
  http_hardening: 'HTTP Hardening',
  grpc_mtls: 'gRPC / mTLS',
  dns_pki: 'DNS / PKI',
  api_exposure: 'API Exposure',
  protocol_modernity: 'Protocol Modernity',
  attack_surface: 'Attack Surface',
  operational: 'Operational',
}

function Scorecard({ score, grade, dimensions, t }) {
  if (score == null) return null
  return (
    <div className="rounded-2xl border border-violet-500/30 bg-violet-500/5 p-6 mb-6">
      <div className="flex flex-wrap items-center gap-8 mb-4">
        <div>
          <div className="text-[10px] font-mono uppercase tracking-wider text-[var(--text-muted)]">{t('pages.transportSecurity.score', 'Transport posture')}</div>
          <div className="text-4xl font-mono font-bold text-white mt-1">{score}<span className="text-lg text-[var(--text-muted)]">/100</span></div>
        </div>
        {grade && (
          <div>
            <div className="text-[10px] font-mono uppercase tracking-wider text-[var(--text-muted)]">{t('pages.transportSecurity.grade', 'Grade')}</div>
            <div className="text-4xl font-mono font-bold mt-1" style={{ color: gradeColor(grade) }}>{grade}</div>
          </div>
        )}
      </div>
      {dimensions && typeof dimensions === 'object' && (
        <div className="grid grid-cols-2 sm:grid-cols-4 gap-3 pt-4 border-t border-[var(--border-default)]">
          {Object.entries(dimensions).map(([k, v]) => (
            <div key={k} className="rounded-lg bg-[var(--table-surface)] border border-[var(--border-subtle)] px-3 py-2">
              <div className="text-[9px] font-mono uppercase text-[var(--text-muted)] truncate">{DIM_LABELS[k] || k}</div>
              <div className="text-lg font-mono font-semibold mt-0.5" style={{ color: gradeColor(v >= 90 ? 'A' : v >= 75 ? 'B' : v >= 60 ? 'C' : 'D') }}>{v}</div>
            </div>
          ))}
        </div>
      )}
    </div>
  )
}

export default function TransportSecurityCommandCenter() {
  const { t } = useTranslation()
  const [clients, setClients] = useState([])
  const [clientId, setClientId] = useState('')
  const { postScan } = useCommandCenterScan(clientId)
  const [target, setTarget] = useState('')
  const [targetTouched, setTargetTouched] = useState(false)
  const [profile, setProfile] = useState('full')
  const [intensity, setIntensity] = useState('normal')
  const [ports, setPorts] = useState('443,8443')
  const [grpcPorts, setGrpcPorts] = useState('50051,9090')
  const [grpcPaths, setGrpcPaths] = useState('')
  const [sni, setSni] = useState('')
  const [timeoutMs, setTimeoutMs] = useState('6000')
  const [toggles, setToggles] = useState(() => Object.fromEntries(PROBE_TOGGLES.map((x) => [x.key, x.defaultVal])))
  const [showParams, setShowParams] = useState(true)
  const [findings, setFindings] = useState([])
  const [status, setStatus] = useState('idle')
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

  const showToast = useCallback((sev, msg) => {
    setToast({ sev, msg })
    setTimeout(() => setToast(null), 5000)
  }, [])

  useEffect(() => {
    apiFetch('/api/clients').then(async (r) => {
      if (!r.ok) return
      const d = await r.json()
      setClients(Array.isArray(d) ? d : d.clients || [])
    }).catch(() => {})
  }, [])

  useEffect(() => {
    if (targetTouched || !clientId) return
    const c = clients.find((x) => String(x.id) === String(clientId))
    const ft = firstClientTarget(c)
    if (ft) setTarget(ft)
  }, [clientId, clients, targetTouched])

  useJobPoll(pendingJobId, {
    enabled: Boolean(pendingJobId),
    onUpdate: (job) => {
      if (job?.status) setStatus(uiJobStatus(job.status))
    },
    onComplete: async (job) => {
      setPendingJobId(null)
      setStatus('completed')
      setLastRun(new Date().toLocaleString())
      const fs = await resolveJobFindings(job, ENGINE, clientId)
      setFindings(Array.isArray(fs) ? fs : [])
      setLastUpdated(new Date().toISOString())
      if (job?.id) setLastJobId(String(job.id))
    },
  })

  const buildBody = useCallback(() => {
    const params = {
      scan_profile: profile,
      intensity,
      ports,
      grpc_ports: grpcPorts,
      grpc_paths: grpcPaths,
      timeout_ms: Number(timeoutMs) || 6000,
      ...Object.fromEntries(
        Object.entries(toggles).map(([k, v]) => [k, typeof v === 'boolean' ? (v ? 'on' : 'off') : v]),
      ),
    }
    if (sni.trim()) params.sni = sni.trim()
    const body = { engine: ENGINE, target: target.trim(), params }
    if (clientId) body.client_id = Number(clientId)
    return body
  }, [profile, intensity, ports, grpcPorts, grpcPaths, sni, timeoutMs, toggles, target, clientId])

  const hubScanParams = useMemo(() => {
    const { engine, target, client_id, ...rest } = buildBody()
    return rest
  }, [buildBody])
  useSyncHubScanParams(ENGINE, hubScanParams)

  const handleRun = useCallback(async () => {
    if (!clientId) { showToast('error', t('pages.transportSecurity.select_client', 'Select a client first')); return }
    if (!target.trim()) { showToast('error', t('pages.transportSecurity.target_required', 'Target required')); return }
    setStatus('running'); setFindings([])
    try {
      const { ok, data: d } = await postScan(buildBody())
      if (!ok) { setStatus('error'); showToast('error', d.detail || 'Scan failed'); return }
      const jobId = d.job_id ?? ''
      showToast('info', t('pages.transportSecurity.queued', 'Transport scan queued ({{id}})', { id: jobId }))
      if (jobId) setPendingJobId(jobId); else setStatus('error')
    } catch (e) {
      setStatus('error'); showToast('error', e?.message ?? 'Scan failed')
    }
  }, [clientId, target, buildBody, showToast, t])

  const score = useMemo(() => extractScore(findings), [findings])
  const grade = useMemo(() => extractGrade(findings), [findings])
  const dimensions = useMemo(() => extractDimensions(findings), [findings])
  const statusColor = { idle: '#475569', running: ACCENT, completed: '#4ade80', error: '#ef4444' }[status]

  return (
    <PageShell
      hideHubParams
      title={t('pages.transportSecurity.title', 'Transport Security Command Center')}
      badge={t('pages.transportSecurity.badge', 'TLS / mTLS / gRPC / HTTP HARDENING')}
      badgeColor={ACCENT}
      subtitle={t('pages.transportSecurity.subtitle', 'Agentless world-class transport posture: live TLS handshakes, weak-crypto matrix, gRPC/gRPC-Web/Connect-RPC, mTLS enforcement, HSTS/CSP/cookies, h2c/HTTP/3, DANE/CAA/CT, TRACE/CORS, cert fingerprint matrix, attack-path synthesis & 0–100 grade — every finding evidence-backed.')}
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
        <div className={`fixed top-16 right-4 z-50 rounded-xl border px-4 py-3 text-sm font-mono max-w-sm shadow-2xl ${toast.sev === 'error' ? 'bg-rose-950/90 border-rose-500/40 text-rose-200' : 'bg-[var(--bg-1)] border-violet-500/30 text-violet-200'}`}>
          {toast.msg}
        </div>
      )}

      <div className="rounded-2xl bg-[var(--bg-2)] backdrop-blur-md border border-[var(--border-default)] p-5 mb-6">
        <div className="flex flex-wrap items-end gap-4">
          <div className="flex flex-col gap-1">
            <label className="text-[10px] font-mono uppercase tracking-wider text-[var(--text-muted)]">{t('pages.transportSecurity.client', 'Client')}</label>
            <select value={clientId} onChange={(e) => { setClientId(e.target.value); setTargetTouched(false) }}
              className="bg-[var(--scrim)] border border-[var(--border-default)] rounded-lg px-3 py-2 text-xs text-[var(--text-secondary)] font-mono min-w-[180px]">
              <option value="">{t('pages.transportSecurity.select_client_opt', '— Select —')}</option>
              {clients.map((c) => <option key={c.id} value={c.id}>{c.name}</option>)}
            </select>
          </div>
          <div className="flex flex-col gap-1 flex-1 min-w-[200px]">
            <label className="text-[10px] font-mono uppercase tracking-wider text-[var(--text-muted)]">{t('pages.transportSecurity.target', 'Target')}</label>
            <input type="text" value={target} onChange={(e) => { setTarget(e.target.value); setTargetTouched(true) }} placeholder="https://api.example.com"
              className="bg-[var(--scrim)] border border-[var(--border-default)] rounded-lg px-3 py-2 text-xs text-[var(--text-secondary)] font-mono" />
          </div>
          <div className="flex flex-col gap-1">
            <label className="text-[10px] font-mono uppercase tracking-wider text-[var(--text-muted)]">{t('pages.transportSecurity.profile', 'Profile')}</label>
            <select value={profile} onChange={(e) => setProfile(e.target.value)} className="bg-[var(--scrim)] border border-[var(--border-default)] rounded-lg px-3 py-2 text-xs text-[var(--text-secondary)] font-mono">
              {['full', 'tls_only', 'headers_only', 'quick', 'grpc_only', 'grpc_deep', 'mtls_audit', 'api_hardening'].map((p) => (
                <option key={p} value={p}>{p}</option>
              ))}
            </select>
          </div>
          <div className="flex flex-col gap-1">
            <label className="text-[10px] font-mono uppercase tracking-wider text-[var(--text-muted)]">{t('pages.transportSecurity.intensity', 'Intensity')}</label>
            <select value={intensity} onChange={(e) => setIntensity(e.target.value)} className="bg-[var(--scrim)] border border-[var(--border-default)] rounded-lg px-3 py-2 text-xs text-[var(--text-secondary)] font-mono">
              <option value="light">light</option>
              <option value="normal">normal</option>
              <option value="aggressive">aggressive</option>
            </select>
          </div>
          <div className="flex items-center gap-2">
            <span className="w-2 h-2 rounded-full" style={{ backgroundColor: statusColor }} />
            <span className="text-[10px] font-mono text-[var(--text-muted)] uppercase">{status}</span>
          </div>
          <button type="button" onClick={handleRun} disabled={status === 'running' || !clientId}
            className="px-5 py-2 rounded-xl font-mono text-sm border border-violet-500/40 text-violet-300 bg-violet-500/10 hover:bg-violet-500/20 disabled:opacity-40">
            {status === 'running' ? '⟳ Scanning…' : '▶ Run Transport Scan'}
          </button>
          <button type="button" onClick={() => setShowParams((s) => !s)} className="px-3 py-2 rounded-xl font-mono text-xs border border-[var(--border-default)] text-[var(--text-tertiary)]">
            {showParams ? '▾ Params' : '▸ Params'}
          </button>
        </div>

        <AnimatePresence initial={false}>
          {showParams && (
            <motion.div initial={{ height: 0, opacity: 0 }} animate={{ height: 'auto', opacity: 1 }} exit={{ height: 0, opacity: 0 }} className="overflow-hidden">
              <div className="mt-5 pt-5 border-t border-[var(--border-subtle)] grid grid-cols-1 lg:grid-cols-3 gap-6">
                <div className="grid grid-cols-1 gap-1.5 max-h-[420px] overflow-y-auto pr-1">
                  {PROBE_TOGGLES.map((tg) => (
                    <label key={tg.key} title={tg.hint} className="flex items-center gap-2 text-xs font-mono text-[var(--text-secondary)] cursor-pointer">
                      <input type="checkbox" checked={!!toggles[tg.key]} onChange={(e) => setToggles((p) => ({ ...p, [tg.key]: e.target.checked }))} className="accent-violet-500" />
                      {tg.label}
                    </label>
                  ))}
                </div>
                <div className="space-y-3">
                  <div>
                    <label className="text-[10px] font-mono text-[var(--text-muted)] block mb-1">TLS ports</label>
                    <input value={ports} onChange={(e) => setPorts(e.target.value)} className="w-full bg-[var(--scrim)] border border-[var(--border-default)] rounded-lg px-3 py-2 text-xs font-mono text-[var(--text-secondary)]" />
                  </div>
                  <div>
                    <label className="text-[10px] font-mono text-[var(--text-muted)] block mb-1">gRPC ports</label>
                    <input value={grpcPorts} onChange={(e) => setGrpcPorts(e.target.value)} className="w-full bg-[var(--scrim)] border border-[var(--border-default)] rounded-lg px-3 py-2 text-xs font-mono text-[var(--text-secondary)]" />
                  </div>
                  <div>
                    <label className="text-[10px] font-mono text-[var(--text-muted)] block mb-1">SNI override</label>
                    <input value={sni} onChange={(e) => setSni(e.target.value)} placeholder="api.example.com" className="w-full bg-[var(--scrim)] border border-[var(--border-default)] rounded-lg px-3 py-2 text-xs font-mono text-[var(--text-secondary)]" />
                  </div>
                </div>
                  <div>
                    <label className="text-[10px] font-mono text-[var(--text-muted)] block mb-1">Custom gRPC paths</label>
                    <input value={grpcPaths} onChange={(e) => setGrpcPaths(e.target.value)} placeholder="/my.Service/Method" className="w-full bg-[var(--scrim)] border border-[var(--border-default)] rounded-lg px-3 py-2 text-xs font-mono text-[var(--text-secondary)]" />
                  </div>
                  <div>
                    <label className="text-[10px] font-mono text-[var(--text-muted)] block mb-1">Timeout (ms)</label>
                  <input type="number" min={400} max={30000} value={timeoutMs} onChange={(e) => setTimeoutMs(e.target.value)}
                    className="w-full bg-[var(--scrim)] border border-[var(--border-default)] rounded-lg px-3 py-2 text-xs font-mono text-[var(--text-secondary)]" />
                </div>
              </div>
            </motion.div>
          )}
        </AnimatePresence>
        {lastRun && <p className="text-[10px] font-mono text-[var(--text-disabled)] mt-3">Last: {lastRun}</p>}
      </div>

      {findings.length > 0 && <Scorecard score={score} grade={grade} dimensions={dimensions} t={t} />}
      {detailFindings.length > 0 && <CategoryBreakdown findings={detailFindings} />}

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
        emptyReadyTitle={t('pages.transportSecurity.run_hint', 'Run a scan to assess TLS, mTLS, gRPC and HTTP hardening.')}
        emptyReadyBody={t('pages.transportSecurity.no_findings', 'No transport exposure observed.')}
        renderFinding={(f, i) => <FindingCard key={i} f={f} />}
      />
    </PageShell>
  )
}
