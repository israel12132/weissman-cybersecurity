import React, { useState, useEffect, useCallback, useMemo } from 'react'
import { useTranslation } from 'react-i18next'
import { motion, AnimatePresence } from 'framer-motion'
import PageShell from './PageShell'
import ShellScanActions from '../components/engine/ShellScanActions'
import WeissmanFindingsPanel from '../components/engine/WeissmanFindingsPanel'
import { useFindingsWorkbench } from '../hooks/useFindingsWorkbench'
import { useEngineHistory } from '../hooks/useEngineHistory'
import { apiFetch } from '../lib/apiBase'
import { useJobPoll, resolveJobFindings, extractFindingsFromJob, uiJobStatus } from '../lib/useJobPoll'

const ENGINE = 'pki_tls'
const ACCENT = '#06b6d4'

const GRADE_COLORS = {
  'A+': '#34d399',
  A: '#4ade80',
  B: '#a3e635',
  C: '#fbbf24',
  D: '#fb923c',
  E: '#f87171',
  F: '#ef4444',
  T: '#f472b6',
}

const SEV_STYLE = {
  critical: { text: 'text-rose-300', bd: 'border-rose-500/40', bg: 'bg-rose-500/10' },
  high: { text: 'text-orange-300', bd: 'border-orange-500/40', bg: 'bg-orange-500/10' },
  medium: { text: 'text-amber-300', bd: 'border-amber-500/40', bg: 'bg-amber-500/10' },
  low: { text: 'text-sky-300', bd: 'border-sky-500/40', bg: 'bg-sky-500/10' },
  info: { text: 'text-slate-300', bd: 'border-white/10', bg: 'bg-white/5' },
}

const PROBE_TOGGLES = [
  { key: 'check_protocols', label: 'Protocol matrix', hint: 'SSLv3 → TLS 1.3 forced handshakes', defaultVal: true },
  { key: 'check_ciphers', label: 'Cipher enumeration', hint: 'Iterative suite discovery per protocol', defaultVal: true },
  { key: 'check_certificate', label: 'Certificate forensics', hint: 'Leaf key, signature, validity, SAN', defaultVal: true },
  { key: 'check_chain_trust', label: 'Chain trust verification', hint: 'OpenSSL verify_result on full chain', defaultVal: true },
  { key: 'check_hostname', label: 'Hostname / SAN match', hint: 'SNI vs certificate names', defaultVal: true },
  { key: 'check_forward_secrecy', label: 'Forward secrecy', hint: 'ECDHE/DHE cipher requirement', defaultVal: true },
  { key: 'check_vulnerabilities', label: 'Vulnerability heuristics', hint: 'POODLE, BEAST, SWEET32, RC4, EXPORT', defaultVal: true },
  { key: 'check_ocsp', label: 'OCSP stapling', hint: 'StatusRequest extension in handshake', defaultVal: true },
  { key: 'check_http_headers', label: 'HSTS & redirect', hint: 'Strict-Transport-Security + HTTP→HTTPS', defaultVal: true },
  { key: 'check_security_headers', label: 'Security headers', hint: 'X-Content-Type-Options, CSP, X-Frame-Options', defaultVal: true },
  { key: 'check_ct_logs', label: 'Certificate Transparency', hint: 'crt.sh passive inventory', defaultVal: true },
  { key: 'check_caa', label: 'DNS CAA policy', hint: 'CA issuance restriction records', defaultVal: true },
]

const DEFAULT_PARAMS = {
  ports: '443',
  sni: '',
  starttls: 'none',
  intensity: 'normal',
  protocols: '',
  timeout_ms: 4000,
  cipher_enumeration_limit: 80,
  port_budget_secs: 45,
  expiry_warning_days: 30,
  ...Object.fromEntries(PROBE_TOGGLES.map((t) => [t.key, t.defaultVal])),
}

function gradeColor(grade) {
  if (!grade) return '#94a3b8'
  const base = String(grade).split(/[\s(]/)[0]
  return GRADE_COLORS[base] || '#94a3b8'
}

function firstClientTarget(client) {
  if (!client) return ''
  let domains = client.domains
  if (typeof domains === 'string') {
    try { domains = JSON.parse(domains) } catch { domains = [] }
  }
  const first = Array.isArray(domains) ? domains.find((d) => typeof d === 'string' && d.trim()) : ''
  if (!first) return ''
  return first.replace(/^https?:\/\//, '').split('/')[0]
}

function isGradeSummary(f) {
  return typeof f?.title === 'string' && f.title.includes('TLS posture grade')
}

function extractGrade(findings) {
  const summary = findings.find(isGradeSummary)
  if (!summary) return null
  const fromEv = summary.evidence?.grade
  if (fromEv) return String(fromEv)
  const m = summary.title.match(/grade:\s*(.+)$/i)
  return m ? m[1].trim() : null
}

function extractProtocols(findings) {
  const summary = findings.find(isGradeSummary)
  const protos = summary?.evidence?.protocols
  return Array.isArray(protos) ? protos : []
}

function extractCiphers(findings) {
  const summary = findings.find(isGradeSummary)
  const ciphers = summary?.evidence?.ciphers
  return Array.isArray(ciphers) ? ciphers : []
}

function Toggle({ label, hint, checked, onChange }) {
  return (
    <button type="button" onClick={() => onChange(!checked)} className="w-full flex items-center justify-between gap-3 px-3 py-2 rounded-lg bg-white/5 border border-white/5 hover:bg-white/10 transition-all text-left">
      <span className="min-w-0">
        <span className="block text-[12px] font-mono text-white/85 truncate">{label}</span>
        {hint && <span className="block text-[10px] font-mono text-white/35 truncate">{hint}</span>}
      </span>
      <span className={`shrink-0 w-9 h-5 rounded-full relative transition-colors ${checked ? 'bg-cyan-500/70' : 'bg-white/15'}`}>
        <span className={`absolute top-0.5 w-4 h-4 rounded-full bg-white transition-all ${checked ? 'left-[18px]' : 'left-0.5'}`} />
      </span>
    </button>
  )
}

function EvidenceView({ evidence }) {
  if (!evidence || typeof evidence !== 'object') return null
  const { checks, ...fields } = evidence
  const entries = Object.entries(fields).filter(([k]) => k !== 'checks')
  return (
    <div className="mt-2 rounded-lg bg-black/40 border border-white/5 p-3 space-y-2">
      {entries.length > 0 && (
        <div className="grid grid-cols-1 sm:grid-cols-2 gap-x-4 gap-y-1">
          {entries.map(([k, v]) => (
            <div key={k} className="flex items-start gap-2 text-[11px] font-mono">
              <span className="text-white/35 shrink-0">{k}</span>
              <span className="text-white/70 break-all">{typeof v === 'object' ? JSON.stringify(v) : String(v)}</span>
            </div>
          ))}
        </div>
      )}
      {Array.isArray(checks) && checks.length > 0 && (
        <div className="space-y-1 pt-1 border-t border-white/5">
          {checks.map((c, i) => (
            <div key={i} className="flex items-center gap-2 text-[11px] font-mono">
              <span className={c.observed ? 'text-emerald-400' : 'text-white/30'}>{c.observed ? '✓' : '·'}</span>
              <span className="text-white/60">{c.name}</span>
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
  const style = SEV_STYLE[sev] || SEV_STYLE.info
  return (
    <div className={`rounded-xl border ${style.bd} ${style.bg} overflow-hidden`}>
      <button type="button" onClick={() => setOpen((o) => !o)} className="w-full flex items-start gap-3 px-3 py-2.5 text-left hover:bg-white/5">
        <span className={`text-[9px] font-mono px-1.5 py-0.5 rounded border uppercase ${style.text} ${style.bd}`}>{sev}</span>
        <span className="min-w-0 flex-1 text-[12px] font-mono text-white/90">{f.title || f.type}</span>
        <span className="text-white/30 text-xs">{open ? '▾' : '▸'}</span>
      </button>
      <AnimatePresence initial={false}>
        {open && (
          <motion.div initial={{ height: 0, opacity: 0 }} animate={{ height: 'auto', opacity: 1 }} exit={{ height: 0, opacity: 0 }} className="px-3 pb-3">
            <p className="text-[11px] font-mono text-white/55 leading-relaxed">{f.description}</p>
            {f.remediation && <p className="mt-2 text-[10px] font-mono text-cyan-300/80">{f.remediation}</p>}
            <EvidenceView evidence={f.evidence} />
          </motion.div>
        )}
      </AnimatePresence>
    </div>
  )
}

export default function TlsPosture() {
  const { t } = useTranslation()
  const [clients, setClients] = useState([])
  const [selectedClientId, setSelectedClientId] = useState(null)
  const [target, setTarget] = useState('')
  const [params, setParams] = useState(DEFAULT_PARAMS)
  const [scanning, setScanning] = useState(false)
  const [pendingJobId, setPendingJobId] = useState(null)
  const [findings, setFindings] = useState([])
  const [toast, setToast] = useState(null)

  useJobPoll(pendingJobId, {
    enabled: Boolean(pendingJobId),
    onComplete: async (job) => {
      const resolved = await resolveJobFindings(job, ENGINE, selectedClientId)
      const fromJob = extractFindingsFromJob(job)
      setFindings(resolved.length ? resolved : fromJob)
      setScanning(false)
      setPendingJobId(null)
    },
  })

  useEffect(() => {
    apiFetch('/api/clients')
      .then((r) => (r.ok ? r.json() : []))
      .then((d) => { if (Array.isArray(d)) setClients(d) })
      .catch(() => {})
  }, [])

  useEffect(() => {
    if (!selectedClientId) return
    const client = clients.find((c) => String(c.id) === String(selectedClientId))
    const host = firstClientTarget(client)
    if (host) setTarget(host)
  }, [selectedClientId, clients])

  const showToast = useCallback((sev, msg) => {
    const id = Date.now()
    setToast({ id, sev, msg })
    setTimeout(() => setToast((cur) => (cur?.id === id ? null : cur)), 5000)
  }, [])

  const setParam = useCallback((key, val) => {
    setParams((p) => ({ ...p, [key]: val }))
  }, [])

  const grade = useMemo(() => extractGrade(findings), [findings])
  const protocols = useMemo(() => extractProtocols(findings), [findings])
  const ciphers = useMemo(() => extractCiphers(findings), [findings])
  const detailFindings = useMemo(() => findings.filter((f) => !isGradeSummary(f)), [findings])

  const { loadLastRun, historyLoading } = useEngineHistory(ENGINE)
  const {
    exportCsv,
    filteredFindings,
    searchQuery,
    setSearchQuery,
    severityFilter,
    setSeverityFilter,
    counts,
  } = useFindingsWorkbench(detailFindings, { csvPrefix: 'weissman-tls-posture' })

  const reloadLastScan = useCallback(async () => {
    const last = await loadLastRun()
    if (last?.findings?.length) setFindings(last.findings)
  }, [loadLastRun])

  const handleScan = useCallback(async () => {
    if (!selectedClientId) {
      showToast('error', t('pages.tlsPosture.select_client_first'))
      return
    }
    if (!target.trim()) {
      showToast('error', t('pages.tlsPosture.target_required'))
      return
    }
    setScanning(true)
    setFindings([])
    const body = {
      engine: ENGINE,
      client_id: Number(selectedClientId),
      target: target.includes('://') ? target.trim() : `https://${target.trim()}`,
    }
    for (const [k, v] of Object.entries(params)) {
      if (typeof v === 'boolean') body[k] = v ? 'true' : 'false'
      else if (v !== '' && v !== null && v !== undefined) body[k] = v
    }
    try {
      const r = await apiFetch('/api/command-center/scan', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(body),
      })
      const d = await r.json().catch(() => ({}))
      if (!r.ok) {
        showToast('error', d.detail || t('pages.tlsPosture.scan_failed'))
        setScanning(false)
        return
      }
      const jobId = d.job_id ?? ''
      if (jobId) {
        setPendingJobId(jobId)
        showToast('info', t('pages.tlsPosture.scan_queued', { jobId }))
      } else {
        setScanning(false)
      }
    } catch (e) {
      showToast('error', e?.message ?? t('common.error'))
      setScanning(false)
    }
  }, [selectedClientId, target, params, showToast, t])

  const jobStatus = uiJobStatus(pendingJobId, scanning)

  return (
    <PageShell
      title={t('pages.tlsPosture.title')}
      badge={t('pages.tlsPosture.badge')}
      badgeColor={ACCENT}
      subtitle={t('pages.tlsPosture.subtitle')}
      actions={(
        <ShellScanActions
          onRefresh={reloadLastScan}
          onExport={exportCsv}
          refreshLoading={historyLoading || scanning}
          exportDisabled={!filteredFindings.length}
        />
      )}
    >
      {toast && (
        <div className={`fixed top-16 right-4 z-50 rounded-xl border px-4 py-3 text-sm font-mono max-w-sm shadow-2xl ${toast.sev === 'error' ? 'bg-rose-950/90 border-rose-500/40 text-rose-200' : 'bg-black/80 border-cyan-500/30 text-cyan-200'}`}>
          {toast.msg}
        </div>
      )}

      <div className="flex flex-wrap items-center gap-3 mb-6">
        <select
          value={selectedClientId ?? ''}
          onChange={(e) => setSelectedClientId(e.target.value || null)}
          className="bg-black/60 border border-white/10 rounded-lg px-3 py-1.5 text-xs text-white/80 font-mono focus:outline-none focus:border-cyan-500/40"
        >
          <option value="">{t('pages.tlsPosture.select_client')}</option>
          {clients.map((c) => <option key={c.id} value={c.id}>{c.name}</option>)}
        </select>
        <input
          type="text"
          value={target}
          onChange={(e) => setTarget(e.target.value)}
          placeholder={t('pages.tlsPosture.target_placeholder')}
          className="flex-1 min-w-[200px] bg-black/60 border border-white/10 rounded-lg px-3 py-1.5 text-xs font-mono text-white/85 focus:outline-none focus:border-cyan-500/40"
        />
        <button
          type="button"
          onClick={handleScan}
          disabled={scanning || !selectedClientId}
          className="px-5 py-2 rounded-xl font-mono text-sm border border-cyan-500/40 text-cyan-300 bg-cyan-500/10 hover:bg-cyan-500/20 disabled:opacity-40 transition-all"
        >
          {scanning ? t('pages.tlsPosture.scanning') : t('pages.tlsPosture.run_scan')}
        </button>
        {jobStatus && <span className="text-[10px] font-mono text-white/40">{jobStatus}</span>}
      </div>

      <div className="grid grid-cols-1 xl:grid-cols-3 gap-6">
        <motion.section initial={{ opacity: 0, y: 8 }} animate={{ opacity: 1, y: 0 }} className="xl:col-span-1 rounded-2xl bg-black/40 backdrop-blur-md border border-white/10 p-5 space-y-4 max-h-[85vh] overflow-y-auto">
          <h3 className="text-xs font-mono text-white/50 uppercase tracking-widest">{t('pages.tlsPosture.control_panel')}</h3>

          <label className="block text-[10px] font-mono text-white/40 uppercase tracking-widest">
            {t('pages.tlsPosture.tls_ports')}
            <input type="text" value={params.ports} onChange={(e) => setParam('ports', e.target.value)} className="mt-1 w-full bg-black/50 border border-white/10 rounded-md px-2 py-1.5 text-[11px] font-mono text-white/80" placeholder="443,8443,993" />
          </label>

          <label className="block text-[10px] font-mono text-white/40 uppercase tracking-widest">
            {t('pages.tlsPosture.sni')}
            <input type="text" value={params.sni} onChange={(e) => setParam('sni', e.target.value)} className="mt-1 w-full bg-black/50 border border-white/10 rounded-md px-2 py-1.5 text-[11px] font-mono text-white/80" />
          </label>

          <label className="block text-[10px] font-mono text-white/40 uppercase tracking-widest">
            {t('pages.tlsPosture.starttls')}
            <select value={params.starttls} onChange={(e) => setParam('starttls', e.target.value)} className="mt-1 w-full bg-black/50 border border-white/10 rounded-md px-2 py-1.5 text-[11px] font-mono text-white/80">
              {['none', 'auto', 'smtp', 'imap', 'pop3', 'ftp'].map((o) => <option key={o} value={o}>{o}</option>)}
            </select>
          </label>

          <label className="block text-[10px] font-mono text-white/40 uppercase tracking-widest">
            {t('pages.tlsPosture.intensity')}
            <select value={params.intensity} onChange={(e) => setParam('intensity', e.target.value)} className="mt-1 w-full bg-black/50 border border-white/10 rounded-md px-2 py-1.5 text-[11px] font-mono text-white/80">
              <option value="light">{t('pages.tlsPosture.intensity_light')}</option>
              <option value="normal">{t('pages.tlsPosture.intensity_normal')}</option>
              <option value="aggressive">{t('pages.tlsPosture.intensity_aggressive')}</option>
            </select>
          </label>

          <label className="block text-[10px] font-mono text-white/40 uppercase tracking-widest">
            {t('pages.tlsPosture.protocols_filter')}
            <input type="text" value={params.protocols} onChange={(e) => setParam('protocols', e.target.value)} placeholder="tls1.2,tls1.3" className="mt-1 w-full bg-black/50 border border-white/10 rounded-md px-2 py-1.5 text-[11px] font-mono text-white/80" />
          </label>

          <div className="grid grid-cols-2 gap-3">
            <label className="block text-[10px] font-mono text-white/40 uppercase tracking-widest">
              {t('pages.tlsPosture.timeout_ms')}
              <input type="number" min={200} max={30000} value={params.timeout_ms} onChange={(e) => setParam('timeout_ms', Number(e.target.value))} className="mt-1 w-full bg-black/50 border border-white/10 rounded-md px-2 py-1.5 text-[11px] font-mono text-white/80" />
            </label>
            <label className="block text-[10px] font-mono text-white/40 uppercase tracking-widest">
              {t('pages.tlsPosture.cipher_limit')}
              <input type="number" min={1} max={512} value={params.cipher_enumeration_limit} onChange={(e) => setParam('cipher_enumeration_limit', Number(e.target.value))} className="mt-1 w-full bg-black/50 border border-white/10 rounded-md px-2 py-1.5 text-[11px] font-mono text-white/80" />
            </label>
            <label className="block text-[10px] font-mono text-white/40 uppercase tracking-widest">
              {t('pages.tlsPosture.port_budget')}
              <input type="number" min={5} max={600} value={params.port_budget_secs} onChange={(e) => setParam('port_budget_secs', Number(e.target.value))} className="mt-1 w-full bg-black/50 border border-white/10 rounded-md px-2 py-1.5 text-[11px] font-mono text-white/80" />
            </label>
            <label className="block text-[10px] font-mono text-white/40 uppercase tracking-widest">
              {t('pages.tlsPosture.expiry_warning')}
              <input type="number" min={1} max={365} value={params.expiry_warning_days} onChange={(e) => setParam('expiry_warning_days', Number(e.target.value))} className="mt-1 w-full bg-black/50 border border-white/10 rounded-md px-2 py-1.5 text-[11px] font-mono text-white/80" />
            </label>
          </div>

          <div className="pt-2 border-t border-white/5 space-y-2">
            <p className="text-[10px] font-mono text-white/35 uppercase tracking-widest">{t('pages.tlsPosture.probe_toggles')}</p>
            {PROBE_TOGGLES.map((tog) => (
              <Toggle
                key={tog.key}
                label={tog.label}
                hint={tog.hint}
                checked={Boolean(params[tog.key])}
                onChange={(v) => setParam(tog.key, v)}
              />
            ))}
          </div>
        </motion.section>

        <div className="xl:col-span-2 space-y-6">
          <motion.section initial={{ opacity: 0, y: 8 }} animate={{ opacity: 1, y: 0 }} transition={{ delay: 0.05 }} className="rounded-2xl bg-black/40 backdrop-blur-md border border-white/10 p-6">
            <div className="flex flex-wrap items-center gap-6">
              <div className="text-center min-w-[120px]">
                <p className="text-[10px] font-mono text-white/40 uppercase tracking-widest mb-2">{t('pages.tlsPosture.ssl_grade')}</p>
                <p className="text-5xl font-bold font-mono" style={{ color: gradeColor(grade) }}>{grade || '—'}</p>
              </div>
              <div className="flex-1 min-w-[200px]">
                <p className="text-[10px] font-mono text-white/40 uppercase tracking-widest mb-2">{t('pages.tlsPosture.protocol_matrix')}</p>
                {protocols.length === 0 ? (
                  <p className="text-[11px] font-mono text-white/25">{t('pages.tlsPosture.empty_ready')}</p>
                ) : (
                  <div className="flex flex-wrap gap-2">
                    {protocols.map((p) => (
                      <span key={p.version} className={`text-[10px] font-mono px-2 py-1 rounded border ${p.supported ? 'border-emerald-500/40 text-emerald-300 bg-emerald-500/10' : 'border-white/10 text-white/30 bg-white/5'}`}>
                        {p.version}{p.supported ? ' ✓' : ''}
                      </span>
                    ))}
                  </div>
                )}
              </div>
              <div className="text-center min-w-[80px]">
                <p className="text-[10px] font-mono text-white/40 uppercase tracking-widest mb-1">{t('pages.tlsPosture.findings_count')}</p>
                <p className="text-2xl font-bold font-mono text-white">{findings.length}</p>
              </div>
            </div>
          </motion.section>

          {ciphers.length > 0 && (
            <motion.section initial={{ opacity: 0, y: 8 }} animate={{ opacity: 1, y: 0 }} transition={{ delay: 0.08 }} className="rounded-2xl bg-black/40 backdrop-blur-md border border-white/10 p-5">
              <h3 className="text-xs font-mono text-white/50 uppercase tracking-widest mb-3">{t('pages.tlsPosture.cipher_inventory')} ({ciphers.length})</h3>
              <div className="max-h-48 overflow-y-auto space-y-1">
                {ciphers.map((c, i) => (
                  <div key={i} className="flex flex-wrap items-center gap-2 text-[10px] font-mono py-1 border-b border-white/5">
                    <span className="text-cyan-300/90">{c.name}</span>
                    <span className="text-white/30">{c.protocol}</span>
                    <span className="text-white/40">{c.bits}b</span>
                    {c.forward_secrecy && <span className="text-emerald-400/80">PFS</span>}
                    {Array.isArray(c.weaknesses) && c.weaknesses.length > 0 && (
                      <span className="text-amber-300/70 truncate">{c.weaknesses[0]}</span>
                    )}
                  </div>
                ))}
              </div>
            </motion.section>
          )}

          <motion.section initial={{ opacity: 0, y: 8 }} animate={{ opacity: 1, y: 0 }} transition={{ delay: 0.1 }} className="rounded-2xl bg-black/40 backdrop-blur-md border border-white/10 p-5">
            <WeissmanFindingsPanel
              findings={detailFindings}
              filteredFindings={filteredFindings}
              counts={counts}
              total={detailFindings.length}
              searchQuery={searchQuery}
              onSearchChange={setSearchQuery}
              severityFilter={severityFilter}
              onSeverityChange={setSeverityFilter}
              loading={historyLoading}
              pending={scanning}
              accent="#22d3ee"
              title={t('pages.tlsPosture.findings')}
              emptyTitle={t('pages.tlsPosture.empty_ready')}
              emptyBody={t('pages.tlsPosture.empty_ready')}
              renderFinding={(f, i) => <FindingCard key={i} f={f} />}
            />
          </motion.section>
        </div>
      </div>
    </PageShell>
  )
}
