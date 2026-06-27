import { firstClientTarget } from '../lib/clientTarget'
import { useCommandCenterScan } from '../hooks/useCommandCenterScan'
import { useSyncHubScanParams } from '../hooks/useLaunchEngineScan'
import React, { useState, useEffect, useCallback, useMemo } from 'react'
import { useTranslation } from 'react-i18next'
import { motion, AnimatePresence } from 'framer-motion'
import PageShell from './PageShell'
import ShellScanActions from '../components/engine/ShellScanActions'
import WeissmanFindingsPanel from '../components/engine/WeissmanFindingsPanel'
import { useWeissmanEnginePage, applyHistoryFindings } from '../hooks/useWeissmanEnginePage'
import { apiFetch } from '../lib/apiBase'
import { useJobPoll, resolveJobFindings, uiJobStatus } from '../lib/useJobPoll'

const ENGINE = 'pki_tls'
const ACCENT = '#34d399'

const TOGGLES = [
  { key: 'check_protocols', label: 'Protocol matrix', hint: 'Force handshakes per SSL/TLS version', defaultVal: true },
  { key: 'check_ciphers', label: 'Cipher enumeration', hint: 'Iterative !cipher walk per protocol', defaultVal: true },
  { key: 'check_certificate', label: 'Certificate forensics', hint: 'Leaf + chain parsing, expiry, SAN/CN', defaultVal: true },
  { key: 'check_chain_trust', label: 'Chain trust verification', hint: 'OpenSSL verify_result against system trust', defaultVal: true },
  { key: 'check_hostname', label: 'Hostname / SAN match', hint: 'SNI vs certificate identity', defaultVal: true },
  { key: 'check_forward_secrecy', label: 'Forward secrecy', hint: 'Flag suites without ephemeral key exchange', defaultVal: true },
  { key: 'check_vulnerabilities', label: 'Vulnerability heuristics', hint: 'POODLE, BEAST, SWEET32, RC4, weak keys', defaultVal: true },
  { key: 'check_ocsp', label: 'OCSP stapling', hint: 'Status request extension on handshake', defaultVal: true },
  { key: 'check_http_headers', label: 'HSTS / redirect', hint: 'Strict-Transport-Security + HTTP→HTTPS', defaultVal: true },
  { key: 'check_security_headers', label: 'Security headers', hint: 'CSP, X-Frame-Options, X-Content-Type-Options', defaultVal: true },
  { key: 'check_ct_logs', label: 'Certificate Transparency', hint: 'crt.sh issuance history', defaultVal: true },
  { key: 'check_caa', label: 'DNS CAA', hint: 'CA restriction policy in DNS', defaultVal: true },
  { key: 'check_dane', label: 'DANE / TLSA', hint: 'RFC 6698 certificate pinning in DNS', defaultVal: true },
  { key: 'check_posture_score', label: 'Posture score', hint: '0–100 SSL-Labs-style aggregate grade', defaultVal: true },
]

const CATEGORY_META = {
  tls_grade: { label: 'TLS Grades', icon: '🏆', color: '#34d399', order: 1 },
  tls_protocol: { label: 'Protocols', icon: '⇄', color: '#38bdf8', order: 2 },
  tls_cipher: { label: 'Ciphers', icon: '🔐', color: '#a78bfa', order: 3 },
  tls_certificate: { label: 'Certificates', icon: '📜', color: '#fbbf24', order: 4 },
  tls_vulnerability: { label: 'Vulnerabilities', icon: '☠', color: '#fb7185', order: 5 },
  tls_hardening: { label: 'Transport Hardening', icon: '🛡', color: '#4ade80', order: 6 },
  tls_ct: { label: 'Certificate Transparency', icon: '📋', color: '#94a3b8', order: 7 },
  tls_caa: { label: 'CAA Policy', icon: '🌐', color: '#64748b', order: 8 },
  tls_dane: { label: 'DANE / TLSA', icon: '⛓', color: '#22d3ee', order: 9 },
  other: { label: 'Other', icon: '•', color: '#475569', order: 99 },
}

const SEV_STYLE = {
  critical: { text: 'text-rose-300', bd: 'border-rose-500/40', bg: 'bg-rose-500/10', dot: '#fb7185' },
  high: { text: 'text-orange-300', bd: 'border-orange-500/40', bg: 'bg-orange-500/10', dot: '#fb923c' },
  medium: { text: 'text-amber-300', bd: 'border-amber-500/40', bg: 'bg-amber-500/10', dot: '#fbbf24' },
  low: { text: 'text-sky-300', bd: 'border-sky-500/40', bg: 'bg-sky-500/10', dot: '#38bdf8' },
  info: { text: 'text-slate-300', bd: 'border-white/10', bg: 'bg-white/5', dot: '#94a3b8' },
}

function gradeColor(g) {
  const base = String(g || '').replace(/^T \(would be /, '').replace(/\)$/, '').split(/\s/)[0]
  return { 'A+': '#34d399', A: '#4ade80', B: '#a3e635', C: '#fbbf24', D: '#fb923c', E: '#f87171', F: '#ef4444', T: '#f472b6' }[base] || '#94a3b8'
}

function sevValue(s) { return { critical: 4, high: 3, medium: 2, low: 1, info: 0 }[s] ?? 0 }


function csvToArray(s) { return String(s || '').split(/[,\s]+/).map((x) => x.trim()).filter(Boolean) }

function isSummary(f) { return f && (f.category === 'posture_summary' || f.summary === true || typeof f.posture_score === 'number') }

function inferCategory(f) {
  if (f.category && f.category !== 'posture_summary') return f.category
  const t = `${f.title || ''} ${f.type || ''}`.toLowerCase()
  if (t.includes('posture grade') || t.includes('tls grade')) return 'tls_grade'
  if (t.includes('protocol') || t.includes('tls 1.') || t.includes('sslv')) return 'tls_protocol'
  if (t.includes('cipher') || t.includes('rc4') || t.includes('3des') || t.includes('forward secrecy')) return 'tls_cipher'
  if (t.includes('certificate') || t.includes('cert ') || t.includes('chain') || t.includes('ocsp')) return 'tls_certificate'
  if (t.includes('poodle') || t.includes('beast') || t.includes('sweet32') || t.includes('freak') || t.includes('vulnerab')) return 'tls_vulnerability'
  if (t.includes('hsts') || t.includes('redirect') || t.includes('header') || t.includes('security header')) return 'tls_hardening'
  if (t.includes('transparency') || t.includes('crt.sh') || t.includes(' ct ')) return 'tls_ct'
  if (t.includes('caa')) return 'tls_caa'
  if (t.includes('dane') || t.includes('tlsa')) return 'tls_dane'
  return 'other'
}

function EvidenceView({ evidence }) {
  if (!evidence || typeof evidence !== 'object') return null
  const checks = Array.isArray(evidence.checks) ? evidence.checks : []
  const scalars = Object.entries(evidence).filter(([k]) => k !== 'checks')
  return (
    <div className="mt-2 rounded-lg bg-black/40 border border-white/5 p-3 space-y-2">
      {scalars.length > 0 && (
        <div className="grid grid-cols-1 sm:grid-cols-2 gap-x-4 gap-y-1">
          {scalars.map(([k, v]) => (
            <div key={k} className="flex items-start gap-2 text-[11px] font-mono">
              <span className="text-white/35 shrink-0">{k}</span>
              <span className="text-white/70 break-all">{typeof v === 'object' ? JSON.stringify(v) : String(v)}</span>
            </div>
          ))}
        </div>
      )}
      {checks.length > 0 && (
        <div className="space-y-1 pt-1 border-t border-white/5">
          {checks.map((c, i) => (
            <div key={i} className="flex items-center gap-2 text-[11px] font-mono">
              <span className={c.observed ? 'text-emerald-400' : 'text-white/30'}>{c.observed ? '✓' : '·'}</span>
              <span className="text-white/60">{c.name}</span>
              <span className="text-white/30">—</span>
              <span className="text-white/45 break-all">{typeof c.detail === 'object' ? JSON.stringify(c.detail) : String(c.detail)}</span>
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
            {f.mitre_attack && <span className="text-[10px] font-mono text-white/30">· {f.mitre_attack}</span>}
            {typeof f.confidence === 'number' && <span className="text-[10px] font-mono text-white/30">· conf {(f.confidence * 100).toFixed(0)}%</span>}
          </div>
          <div className="text-sm text-white/90 font-medium mt-0.5">{f.title || f.type}</div>
        </div>
        <span className="text-white/30 text-xs mt-1">{open ? '▾' : '▸'}</span>
      </button>
      <AnimatePresence initial={false}>
        {open && (
          <motion.div initial={{ height: 0, opacity: 0 }} animate={{ height: 'auto', opacity: 1 }} exit={{ height: 0, opacity: 0 }} className="overflow-hidden">
            <p className="text-xs text-white/60 leading-relaxed mt-2">{f.description}</p>
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

function ProtocolMatrix({ gradeFindings }) {
  const rows = useMemo(() => {
    const out = []
    for (const f of gradeFindings) {
      const protos = f.evidence?.protocols
      if (!Array.isArray(protos)) continue
      const portMatch = String(f.title || '').match(/\[:(\d+)\]/)
      const port = portMatch ? portMatch[1] : '?'
      out.push({ port, protos, grade: f.evidence?.grade })
    }
    return out
  }, [gradeFindings])
  if (!rows.length) return null
  const versions = ['SSLv3', 'TLSv1.0', 'TLSv1.1', 'TLSv1.2', 'TLSv1.3']
  return (
    <div className="rounded-2xl bg-black/40 border border-white/10 p-5 mb-6">
      <h3 className="text-sm font-mono text-white/70 uppercase tracking-wider mb-4">Protocol Matrix</h3>
      <div className="overflow-x-auto">
        <table className="w-full text-xs font-mono">
          <thead>
            <tr className="text-white/40 border-b border-white/5">
              <th className="text-left py-2 pr-4">Port</th>
              <th className="text-left py-2 pr-4">Grade</th>
              {versions.map((v) => <th key={v} className="text-center py-2 px-2">{v}</th>)}
            </tr>
          </thead>
          <tbody>
            {rows.map((r) => (
              <tr key={r.port} className="border-b border-white/5">
                <td className="py-2 pr-4 text-emerald-300">{r.port}</td>
                <td className="py-2 pr-4" style={{ color: gradeColor(r.grade) }}>{r.grade}</td>
                {versions.map((v) => {
                  const p = r.protos.find((x) => x.version === v)
                  const ok = p?.supported
                  return (
                    <td key={v} className="text-center py-2 px-2">
                      <span className={ok ? 'text-rose-400' : 'text-emerald-400/60'}>{ok ? '●' : '○'}</span>
                    </td>
                  )
                })}
              </tr>
            ))}
          </tbody>
        </table>
      </div>
      <p className="text-[10px] font-mono text-white/30 mt-3">● = negotiated (deprecated versions flagged separately) · ○ = not offered</p>
    </div>
  )
}

function CipherPanel({ gradeFindings }) {
  const ciphers = useMemo(() => {
    const all = []
    for (const f of gradeFindings) {
      const list = f.evidence?.ciphers
      if (!Array.isArray(list)) continue
      const portMatch = String(f.title || '').match(/\[:(\d+)\]/)
      const port = portMatch ? portMatch[1] : '?'
      for (const c of list) all.push({ ...c, port })
    }
    return all.slice(0, 40)
  }, [gradeFindings])
  if (!ciphers.length) return null
  return (
    <div className="rounded-2xl bg-black/40 border border-white/10 p-5 mb-6">
      <h3 className="text-sm font-mono text-white/70 uppercase tracking-wider mb-3">Enumerated Cipher Suites</h3>
      <div className="max-h-64 overflow-y-auto space-y-1">
        {ciphers.map((c, i) => (
          <div key={i} className="flex items-center gap-2 text-[11px] font-mono py-1 border-b border-white/5">
            <span className="text-white/30 w-10 shrink-0">:{c.port}</span>
            <span className="text-white/80 flex-1 truncate">{c.name || c.iana}</span>
            <span className="text-white/40">{c.bits}b</span>
            {c.forward_secrecy && <span className="text-emerald-400/70 text-[10px]">PFS</span>}
            {Array.isArray(c.weaknesses) && c.weaknesses.length > 0 && (
              <span className="text-rose-400/80 text-[10px] truncate max-w-[120px]">{c.weaknesses[0]}</span>
            )}
          </div>
        ))}
      </div>
    </div>
  )
}

function Scorecard({ summary, t }) {
  if (!summary) return null
  const score = summary.posture_score ?? summary.evidence?.posture_score ?? 0
  const grade = summary.grade ?? summary.evidence?.grade ?? 'N/A'
  const color = gradeColor(grade)
  const worst = summary.worst_severity ?? summary.evidence?.worst_severity ?? 'info'
  const st = SEV_STYLE[worst] || SEV_STYLE.info
  const compliance = summary.evidence?.compliance
  return (
    <motion.div initial={{ opacity: 0, y: 8 }} animate={{ opacity: 1, y: 0 }} className="rounded-2xl bg-black/40 backdrop-blur-md border border-white/10 p-6 mb-6">
      <div className="flex flex-col lg:flex-row lg:items-center gap-6">
        <div className="flex items-center gap-5">
          <div className="relative w-28 h-28 shrink-0">
            <svg viewBox="0 0 100 100" className="w-full h-full -rotate-90">
              <circle cx="50" cy="50" r="44" fill="none" stroke="rgba(255,255,255,0.08)" strokeWidth="8" />
              <circle cx="50" cy="50" r="44" fill="none" stroke={color} strokeWidth="8" strokeLinecap="round" strokeDasharray={`${(score / 100) * 276.46} 276.46`} />
            </svg>
            <div className="absolute inset-0 flex flex-col items-center justify-center">
              <span className="text-3xl font-bold" style={{ color }}>{score}</span>
              <span className="text-[10px] font-mono text-white/40">/ 100</span>
            </div>
          </div>
          <div>
            <div className="text-[10px] font-mono uppercase tracking-widest text-white/40">{t('pages.pkiTlsPosture.tls_posture', 'TLS Posture')}</div>
            <div className="text-4xl font-black leading-none" style={{ color }}>{grade}</div>
            <div className="mt-1.5">
              <span className={`text-[10px] font-mono px-2 py-0.5 rounded-full border ${st.bd} ${st.text}`}>
                {t('pages.pkiTlsPosture.worst', 'Worst: {{sev}}', { sev: worst })}
              </span>
            </div>
          </div>
        </div>
        {compliance && (
          <div className="flex-1 grid grid-cols-1 sm:grid-cols-2 gap-3">
            <div className={`rounded-xl border p-3 ${compliance.pci_dss_tls12_plus ? 'border-emerald-500/30 bg-emerald-500/5' : 'border-rose-500/30 bg-rose-500/5'}`}>
              <div className="text-[10px] font-mono uppercase text-white/40 mb-1">PCI-DSS TLS</div>
              <div className={`text-sm font-mono ${compliance.pci_dss_tls12_plus ? 'text-emerald-300' : 'text-rose-300'}`}>
                {compliance.pci_dss_tls12_plus ? 'Compliant' : 'Violations detected'}
              </div>
            </div>
            <div className={`rounded-xl border p-3 ${compliance.nist_sp800_52_rev2 ? 'border-emerald-500/30 bg-emerald-500/5' : 'border-amber-500/30 bg-amber-500/5'}`}>
              <div className="text-[10px] font-mono uppercase text-white/40 mb-1">NIST SP 800-52</div>
              <div className={`text-sm font-mono ${compliance.nist_sp800_52_rev2 ? 'text-emerald-300' : 'text-amber-300'}`}>
                {compliance.nist_sp800_52_rev2 ? 'Aligned' : 'Gaps detected'}
              </div>
            </div>
          </div>
        )}
      </div>
    </motion.div>
  )
}

export default function PkiTlsCommandCenter() {
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

  const [toggles, setToggles] = useState(() => Object.fromEntries(TOGGLES.map((tg) => [tg.key, tg.defaultVal])))
  const [intensity, setIntensity] = useState('normal')
  const [ports, setPorts] = useState('443')
  const [sni, setSni] = useState('')
  const [starttls, setStarttls] = useState('none')
  const [protocols, setProtocols] = useState('')
  const [timeoutMs, setTimeoutMs] = useState(4000)
  const [cipherLimit, setCipherLimit] = useState(80)

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

  useJobPoll(pendingJobId, {
    enabled: Boolean(pendingJobId),
    onComplete: async (job) => {
      setStatus(uiJobStatus(job.status))
      setLastRun(new Date().toLocaleTimeString())
      const fs = await resolveJobFindings(job, ENGINE, clientId)
      setFindings(Array.isArray(fs) ? fs : [])
      setLastUpdated(new Date().toISOString())
      if (pendingJobId) setLastJobId(pendingJobId)
      setPendingJobId(null)
    },
  })

  const buildBody = useCallback(() => {
    const body = {
      engine: ENGINE,
      target: target.trim(),
      ...toggles,
      intensity,
      timeout_ms: Number(timeoutMs) || 4000,
      cipher_enumeration_limit: Number(cipherLimit) || 80,
      ports: csvToArray(ports),
    }
    if (sni.trim()) body.sni = sni.trim()
    if (starttls !== 'none') body.starttls = starttls
    if (protocols.trim()) body.protocols = protocols.trim()
    if (clientId) body.client_id = Number(clientId)
    return body
  }, [target, toggles, intensity, timeoutMs, cipherLimit, ports, sni, starttls, protocols, clientId])

  const hubScanParams = useMemo(() => {
    const { engine, target, client_id, ...rest } = buildBody()
    return rest
  }, [buildBody])
  useSyncHubScanParams(ENGINE, hubScanParams)

  const handleRun = useCallback(async () => {
    if (!clientId) { showToast('error', t('pages.pkiTlsPosture.select_client_first', 'Select a client first')); return }
    if (!target.trim()) { showToast('error', t('pages.pkiTlsPosture.target_required', 'A target host/URL is required')); return }
    setStatus('running'); setFindings([])
    try {
      const { ok, data: d, status } = await postScan(buildBody())
      if (!ok) { setStatus('error'); showToast('error', d.detail || t('pages.pkiTlsPosture.scan_failed', 'Scan failed')); return }
      const jobId = d.job_id ?? ''
      showToast('info', t('pages.pkiTlsPosture.queued', 'TLS scan queued ({{jobId}})', { jobId }))
      if (jobId) setPendingJobId(jobId); else setStatus('error')
    } catch (e) {
      setStatus('error'); showToast('error', e?.message ?? t('pages.pkiTlsPosture.scan_failed', 'Scan failed'))
    }
  }, [clientId, target, buildBody, showToast, t])

  const summary = useMemo(() => findings.find(isSummary), [findings])
  const gradeFindings = useMemo(() => findings.filter((f) => inferCategory(f) === 'tls_grade'), [findings])
  const statusColor = { idle: '#475569', running: '#22d3ee', completed: '#4ade80', error: '#ef4444' }[status]

  return (
    <PageShell
      hideHubParams
      title={t('pages.pkiTlsPosture.title', 'PKI / TLS Command Center')}
      badge={t('pages.pkiTlsPosture.badge', 'SSL-LABS CLASS · LIVE HANDSHAKES')}
      badgeColor="#34d399"
      subtitle={t('pages.pkiTlsPosture.subtitle', 'Real OpenSSL handshakes: protocol matrix, cipher enumeration, certificate forensics, vulnerability heuristics, HSTS/CAA/DANE/CT, SSL-Labs-style grading & PCI/NIST compliance tags. Every control maps 1:1 to engine parameters.')}
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
        <div className={`fixed top-16 right-4 z-50 rounded-xl border px-4 py-3 text-sm font-mono max-w-sm shadow-2xl ${toast.sev === 'error' ? 'bg-rose-950/90 border-rose-500/40 text-rose-200' : 'bg-black/80 border-emerald-500/30 text-emerald-200'}`}>
          {toast.msg}
        </div>
      )}

      <div className="rounded-2xl bg-black/40 backdrop-blur-md border border-white/10 p-5 mb-6">
        <div className="flex flex-wrap items-end gap-4">
          <div className="flex flex-col gap-1">
            <label className="text-[10px] font-mono uppercase tracking-wider text-white/40">{t('pages.pkiTlsPosture.client', 'Client')}</label>
            <select value={clientId} onChange={(e) => { setClientId(e.target.value); setTargetTouched(false) }}
              className="bg-black/60 border border-white/10 rounded-lg px-3 py-2 text-xs text-white/80 font-mono focus:outline-none focus:border-emerald-500/40 min-w-[180px]">
              <option value="">{t('pages.pkiTlsPosture.select_client', '— Select client —')}</option>
              {clients.map((c) => <option key={c.id} value={c.id}>{c.name}</option>)}
            </select>
          </div>
          <div className="flex flex-col gap-1 flex-1 min-w-[220px]">
            <label className="text-[10px] font-mono uppercase tracking-wider text-white/40">{t('pages.pkiTlsPosture.target', 'Target host / URL')}</label>
            <input type="text" value={target} onChange={(e) => { setTarget(e.target.value); setTargetTouched(true) }} placeholder="https://example.com"
              className="bg-black/60 border border-white/10 rounded-lg px-3 py-2 text-xs text-white/80 font-mono focus:outline-none focus:border-emerald-500/40" />
          </div>
          <div className="flex flex-col gap-1">
            <label className="text-[10px] font-mono uppercase tracking-wider text-white/40">{t('pages.pkiTlsPosture.intensity', 'Intensity')}</label>
            <select value={intensity} onChange={(e) => setIntensity(e.target.value)}
              className="bg-black/60 border border-white/10 rounded-lg px-3 py-2 text-xs text-white/80 font-mono focus:outline-none focus:border-emerald-500/40">
              <option value="light">{t('pages.pkiTlsPosture.intensity_light', 'Light')}</option>
              <option value="normal">{t('pages.pkiTlsPosture.intensity_normal', 'Normal')}</option>
              <option value="aggressive">{t('pages.pkiTlsPosture.intensity_aggressive', 'Aggressive')}</option>
            </select>
          </div>
          <div className="flex items-center gap-2">
            <span className="w-2 h-2 rounded-full" style={{ backgroundColor: statusColor, boxShadow: status === 'running' ? '0 0 6px #34d399' : 'none' }} />
            <span className="text-[10px] font-mono text-white/40 uppercase">{status}</span>
          </div>
          <button type="button" onClick={handleRun} disabled={status === 'running' || !clientId}
            className="px-5 py-2 rounded-xl font-mono text-sm border border-emerald-500/40 text-emerald-300 bg-emerald-500/10 hover:bg-emerald-500/20 transition-all disabled:opacity-40 disabled:cursor-not-allowed">
            {status === 'running' ? t('pages.pkiTlsPosture.scanning', '⟳ Scanning…') : t('pages.pkiTlsPosture.run_scan', '▶ Run TLS Assessment')}
          </button>
          <button type="button" onClick={() => setShowParams((s) => !s)}
            className="px-3 py-2 rounded-xl font-mono text-xs border border-white/10 text-white/50 hover:text-white/80 hover:border-white/20 transition-all">
            {showParams ? t('pages.pkiTlsPosture.hide_params', '▾ Parameters') : t('pages.pkiTlsPosture.show_params', '▸ Parameters')}
          </button>
        </div>

        <AnimatePresence initial={false}>
          {showParams && (
            <motion.div initial={{ height: 0, opacity: 0 }} animate={{ height: 'auto', opacity: 1 }} exit={{ height: 0, opacity: 0 }} className="overflow-hidden">
              <div className="mt-5 pt-5 border-t border-white/5 grid grid-cols-1 lg:grid-cols-3 gap-6">
                <div>
                  <div className="text-[10px] font-mono uppercase tracking-wider text-white/40 mb-2">{t('pages.pkiTlsPosture.probe_categories', 'Probe categories')}</div>
                  <div className="grid grid-cols-1 gap-1.5">
                    {TOGGLES.map((tg) => (
                      <label key={tg.key} title={tg.hint} className="flex items-center gap-2 text-xs font-mono text-white/70 cursor-pointer">
                        <input type="checkbox" checked={!!toggles[tg.key]} onChange={(e) => setToggles((p) => ({ ...p, [tg.key]: e.target.checked }))} className="accent-emerald-500" />
                        {tg.label}
                      </label>
                    ))}
                  </div>
                </div>
                <div className="space-y-3">
                  <div>
                    <label className="text-[10px] font-mono uppercase tracking-wider text-white/40 block mb-1">{t('pages.pkiTlsPosture.ports', 'TLS ports')}</label>
                    <input type="text" value={ports} onChange={(e) => setPorts(e.target.value)} placeholder="443,8443,993"
                      className="w-full bg-black/60 border border-white/10 rounded-lg px-3 py-2 text-xs text-white/80 font-mono focus:outline-none focus:border-emerald-500/40" />
                  </div>
                  <div>
                    <label className="text-[10px] font-mono uppercase tracking-wider text-white/40 block mb-1">{t('pages.pkiTlsPosture.sni', 'SNI override')}</label>
                    <input type="text" value={sni} onChange={(e) => setSni(e.target.value)} placeholder="api.example.com"
                      className="w-full bg-black/60 border border-white/10 rounded-lg px-3 py-2 text-xs text-white/80 font-mono focus:outline-none focus:border-emerald-500/40" />
                  </div>
                  <div>
                    <label className="text-[10px] font-mono uppercase tracking-wider text-white/40 block mb-1">{t('pages.pkiTlsPosture.starttls', 'STARTTLS')}</label>
                    <select value={starttls} onChange={(e) => setStarttls(e.target.value)}
                      className="w-full bg-black/60 border border-white/10 rounded-lg px-3 py-2 text-xs text-white/80 font-mono focus:outline-none focus:border-emerald-500/40">
                      {['none', 'auto', 'smtp', 'imap', 'pop3', 'ftp'].map((o) => <option key={o} value={o}>{o}</option>)}
                    </select>
                  </div>
                </div>
                <div className="space-y-3">
                  <div>
                    <label className="text-[10px] font-mono uppercase tracking-wider text-white/40 block mb-1">{t('pages.pkiTlsPosture.protocols', 'Protocols (blank = all)')}</label>
                    <input type="text" value={protocols} onChange={(e) => setProtocols(e.target.value)} placeholder="tls1.2,tls1.3"
                      className="w-full bg-black/60 border border-white/10 rounded-lg px-3 py-2 text-xs text-white/80 font-mono focus:outline-none focus:border-emerald-500/40" />
                  </div>
                  <div>
                    <label className="text-[10px] font-mono uppercase tracking-wider text-white/40 block mb-1">{t('pages.pkiTlsPosture.timeout_ms', 'Handshake timeout (ms)')}</label>
                    <input type="number" min={200} max={30000} value={timeoutMs} onChange={(e) => setTimeoutMs(e.target.value)}
                      className="w-full bg-black/60 border border-white/10 rounded-lg px-3 py-2 text-xs text-white/80 font-mono focus:outline-none focus:border-emerald-500/40" />
                  </div>
                  <div>
                    <label className="text-[10px] font-mono uppercase tracking-wider text-white/40 block mb-1">{t('pages.pkiTlsPosture.cipher_limit', 'Cipher walk depth')}</label>
                    <input type="number" min={1} max={512} value={cipherLimit} onChange={(e) => setCipherLimit(e.target.value)}
                      className="w-full bg-black/60 border border-white/10 rounded-lg px-3 py-2 text-xs text-white/80 font-mono focus:outline-none focus:border-emerald-500/40" />
                  </div>
                </div>
              </div>
            </motion.div>
          )}
        </AnimatePresence>
        {lastRun && <p className="text-[10px] font-mono text-white/25 mt-3">{t('pages.pkiTlsPosture.last_completed', 'Last completed: {{time}}', { time: lastRun })}</p>}
      </div>

      {!clientId && (
        <p className="text-xs font-mono text-white/40 mb-6">{t('pages.pkiTlsPosture.select_client_warning', 'Select an in-scope client and target to run the TLS assessment.')}</p>
      )}

      {findings.length > 0 && <Scorecard summary={summary} t={t} />}
      {findings.length > 0 && <ProtocolMatrix gradeFindings={gradeFindings} />}
      {findings.length > 0 && <CipherPanel gradeFindings={gradeFindings} />}

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
        emptyReadyTitle={t('pages.pkiTlsPosture.run_to_populate', 'Run a TLS assessment to map protocols, ciphers, certificates, and transport hardening with live handshakes.')}
        emptyReadyBody={t('pages.pkiTlsPosture.run_to_populate', 'Run a TLS assessment to map protocols, ciphers, certificates, and transport hardening with live handshakes.')}
        emptyTitle={t('pages.pkiTlsPosture.no_findings', 'No TLS endpoints reachable on the selected ports.')}
        emptyBody={t('pages.pkiTlsPosture.no_findings', 'No TLS endpoints reachable on the selected ports.')}
        renderFinding={(f, i) => <FindingCard key={i} f={f} />}
      />
    </PageShell>
  )
}
