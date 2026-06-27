import { firstClientTarget } from '../lib/clientTarget'
import { useCommandCenterScan } from '../hooks/useCommandCenterScan'
import { useSyncHubScanParams } from '../hooks/useLaunchEngineScan'
import React, { useState, useEffect, useCallback, useMemo } from 'react'
import { motion, AnimatePresence } from 'framer-motion'
import PageShell from './PageShell'
import ShellScanActions from '../components/engine/ShellScanActions'
import WeissmanFindingsPanel from '../components/engine/WeissmanFindingsPanel'
import { useWeissmanEnginePage, applyHistoryFindings } from '../hooks/useWeissmanEnginePage'
import { apiFetch } from '../lib/apiBase'
import { useJobPoll, resolveJobFindings, uiJobStatus } from '../lib/useJobPoll'

const ENGINE = 'asm'
const ACCENT = '#22d3ee'

// ─── Constants ────────────────────────────────────────────────────────────────

const SEVERITY_META = {
  critical: { color: '#ef4444', label: 'Critical' },
  high: { color: '#f97316', label: 'High' },
  medium: { color: '#f59e0b', label: 'Medium' },
  low: { color: '#22d3ee', label: 'Low' },
  info: { color: '#6b7280', label: 'Info' },
}

const ASSET_META = {
  inventory: { icon: '🗂', label: 'Asset Inventory' },
  dns: { icon: '🧭', label: 'DNS Intelligence' },
  email_posture: { icon: '✉️', label: 'Email Spoofing' },
  port: { icon: '🔌', label: 'Service Exposure' },
  banner: { icon: '📡', label: 'Service Banners' },
  http_posture: { icon: '🌐', label: 'HTTP Posture' },
  tls_posture: { icon: '🔒', label: 'TLS / Certificates' },
  cloud_footprint: { icon: '☁️', label: 'Cloud Footprint' },
  fingerprint: { icon: '🧬', label: 'Technology Stack' },
  cloud_hunter: { icon: '🎯', label: 'Subdomain Takeover' },
  shadow_it: { icon: '👻', label: 'Shadow IT' },
  attack_path: { icon: '⛓', label: 'Attack Path' },
  wellknown: { icon: '📋', label: 'Well-Known URIs' },
  rdap: { icon: '🏛', label: 'RDAP / Registration' },
  asn: { icon: '🛰', label: 'ASN Attribution' },
  cors: { icon: '🔀', label: 'CORS Policy' },
  sensitive_path: { icon: '🚨', label: 'Sensitive Paths' },
  robots: { icon: '🤖', label: 'robots.txt Intel' },
  report: { icon: '📊', label: 'Summary' },
}

// All knobs map 1:1 to EngineRunContext::job_params keys read by asm_engine::run_asm_result_ctx.
const DEFAULT_PARAMS = {
  ports: 'top',
  port_scan: true,
  subdomain_enum: true,
  subdomain_sources: 'both',
  max_subdomains: 50,
  dns_intel: true,
  dns_hardening: true,
  dkim_probe: true,
  rdap_intel: true,
  ip_asn_enrichment: true,
  http_posture: true,
  tls_posture: true,
  cloud_hunter: true,
  tech_fingerprint: true,
  shadow_it_scan: true,
  wellknown_probe: true,
  cleartext_http_probe: true,
  banner_grab: true,
  cors_probe: true,
  sensitive_path_probe: true,
  robots_harvest: true,
  attack_path_correlation: true,
  severity_threshold: 'info',
  port_timeout_ms: 500,
  http_timeout_ms: 6000,
  max_findings: 800,
  subdomain_wordlist: '',
}

const TOGGLES = [
  { key: 'port_scan', label: 'Service / Port exposure', hint: 'TCP probe of exposed ports & services' },
  { key: 'banner_grab', label: 'TCP service banners', hint: 'Post-connect banner reads (SSH, HTTP, DB protocols)' },
  { key: 'subdomain_enum', label: 'Subdomain discovery', hint: 'Passive CT + active DNS brute-force' },
  { key: 'dns_intel', label: 'DNS & email posture', hint: 'A/AAAA/MX/NS/TXT + SPF/DMARC' },
  { key: 'dkim_probe', label: 'DKIM selector discovery', hint: 'Live TXT lookups for common DKIM selectors' },
  { key: 'dns_hardening', label: 'DNS hardening', hint: 'Wildcard DNS + CAA coverage gaps' },
  { key: 'rdap_intel', label: 'RDAP registration intel', hint: 'Registrar, NS delegation, expiry/hold status' },
  { key: 'ip_asn_enrichment', label: 'IP → ASN enrichment', hint: 'Team Cymru origin lookup for apex A records' },
  { key: 'http_posture', label: 'HTTP security posture', hint: 'Security headers, disclosure, cookies' },
  { key: 'cors_probe', label: 'CORS misconfiguration', hint: 'Reflective Origin / wildcard credential risks' },
  { key: 'sensitive_path_probe', label: 'Sensitive path exposure', hint: 'Read-only probes for .env, backups, actuators' },
  { key: 'robots_harvest', label: 'robots.txt intelligence', hint: 'Surfaces disallowed admin/backup paths' },
  { key: 'cleartext_http_probe', label: 'Cleartext HTTP', hint: 'Detects HTTP without HTTPS upgrade' },
  { key: 'wellknown_probe', label: 'Well-known URIs', hint: 'security.txt and RFC 9116 surfaces' },
  { key: 'tls_posture', label: 'TLS / certificate posture', hint: 'Expiry, self-signed, weak protocols' },
  { key: 'cloud_hunter', label: 'Subdomain takeover + storage', hint: 'Dangling CNAMEs, exposed buckets' },
  { key: 'shadow_it_scan', label: 'Shadow IT detection', hint: 'dev/staging/admin/vpn host patterns' },
  { key: 'tech_fingerprint', label: 'Technology fingerprint', hint: 'Detect frameworks & components' },
  { key: 'attack_path_correlation', label: 'Attack path correlation', hint: 'Toxic combination synthesis (CORS+leaks, etc.)' },
]

// ─── Helpers ──────────────────────────────────────────────────────────────────


function severityColor(s) {
  return SEVERITY_META[(s || 'info').toLowerCase()]?.color ?? '#6b7280'
}

function gradeColor(grade) {
  return { A: '#22c55e', B: '#84cc16', C: '#f59e0b', D: '#f97316', F: '#ef4444' }[grade] ?? '#6b7280'
}

// ─── Small UI pieces ────────────────────────────────────────────────────────

function Toggle({ checked, onChange, disabled }) {
  return (
    <button
      type="button"
      role="switch"
      aria-checked={checked}
      disabled={disabled}
      onClick={() => onChange(!checked)}
      className={`relative shrink-0 w-10 h-5 rounded-full transition-all duration-300 disabled:opacity-40 ${
        checked ? 'bg-cyan-500/40 shadow-[inset_0_0_8px_rgba(34,211,238,0.3)]' : 'bg-black/60 border border-white/10'
      }`}
    >
      <span className={`absolute top-0.5 w-4 h-4 rounded-full bg-white shadow transition-all duration-300 ${checked ? 'left-[22px]' : 'left-0.5'}`} />
    </button>
  )
}

function MetricCard({ label, value, sub, accent = '#22d3ee', icon }) {
  return (
    <div className="relative overflow-hidden rounded-2xl border border-white/[0.08] bg-gradient-to-br from-white/[0.06] to-black/50 p-4">
      <div className="absolute top-0 inset-x-0 h-px opacity-60" style={{ background: `linear-gradient(90deg, transparent, ${accent}60, transparent)` }} />
      <div className="flex items-start justify-between gap-2">
        <div className="min-w-0">
          <p className="text-[10px] font-mono uppercase tracking-[0.18em] text-white/40 mb-1.5">{label}</p>
          <p className="text-2xl font-bold text-white tracking-tight truncate">{value}</p>
          {sub && <p className="text-[10px] font-mono text-white/35 mt-1 truncate">{sub}</p>}
        </div>
        {icon && <span className="text-lg opacity-70 shrink-0">{icon}</span>}
      </div>
    </div>
  )
}

function ScoreRing({ score, grade }) {
  const color = gradeColor(grade)
  const deg = Math.round((Math.max(0, Math.min(100, score)) / 100) * 360)
  return (
    <div className="relative w-36 h-36 shrink-0" title={`Attack Surface Score ${score}/100`}>
      <div
        className="absolute inset-0 rounded-full"
        style={{ background: `conic-gradient(${color} ${deg}deg, rgba(255,255,255,0.06) ${deg}deg)` }}
      />
      <div className="absolute inset-[10px] rounded-full bg-[#0a0f1c] border border-white/10 flex flex-col items-center justify-center">
        <span className="text-4xl font-black" style={{ color }}>{grade}</span>
        <span className="text-[11px] font-mono text-white/55">{score}/100</span>
      </div>
    </div>
  )
}

function SeverityBar({ counts }) {
  const order = ['critical', 'high', 'medium', 'low', 'info']
  const total = order.reduce((a, k) => a + (counts?.[k] ?? 0), 0) || 1
  return (
    <div className="space-y-2 w-full">
      <div className="flex h-2.5 w-full overflow-hidden rounded-full bg-black/50">
        {order.map((k) => {
          const c = counts?.[k] ?? 0
          if (!c) return null
          return <div key={k} style={{ width: `${(c / total) * 100}%`, backgroundColor: SEVERITY_META[k].color }} />
        })}
      </div>
      <div className="flex flex-wrap gap-x-4 gap-y-1">
        {order.map((k) => (
          <span key={k} className="text-[11px] font-mono flex items-center gap-1.5" style={{ color: SEVERITY_META[k].color }}>
            <span className="w-2 h-2 rounded-full inline-block" style={{ backgroundColor: SEVERITY_META[k].color }} />
            {counts?.[k] ?? 0} {SEVERITY_META[k].label}
          </span>
        ))}
      </div>
    </div>
  )
}

function AttackPathPanel({ paths }) {
  if (!paths?.length) return null
  return (
    <div className="rounded-2xl border border-rose-500/25 bg-gradient-to-br from-rose-950/20 to-black/50 p-5">
      <p className="text-[10px] font-mono uppercase tracking-widest text-rose-300/70 mb-3">⛓ Correlated attack paths</p>
      <div className="space-y-2">
        {paths.map((p, i) => {
          const sev = (p.severity || 'critical').toLowerCase()
          return (
            <div key={i} className="rounded-xl border border-rose-500/20 bg-black/40 px-4 py-3">
              <div className="flex items-start justify-between gap-3">
                <p className="text-sm font-semibold text-white/95">{p.title}</p>
                <span className="text-[9px] font-mono uppercase px-2 py-0.5 rounded border" style={{ color: severityColor(sev), borderColor: `${severityColor(sev)}50` }}>{sev}</span>
              </div>
              {p.value && <p className="text-[10px] font-mono text-rose-200/50 mt-1">{p.value}</p>}
            </div>
          )
        })}
      </div>
    </div>
  )
}

function RemediationPanel({ queue }) {
  if (!queue?.length) return null
  return (
    <div className="rounded-2xl border border-emerald-500/20 bg-black/40 p-5">
      <p className="text-[10px] font-mono uppercase tracking-widest text-emerald-300/70 mb-3">→ Priority remediation queue</p>
      <ol className="space-y-2">
        {queue.map((item, i) => (
          <li key={i} className="flex gap-3 text-[12px] font-mono">
            <span className="text-emerald-400/80 shrink-0 w-5">{i + 1}.</span>
            <div className="min-w-0">
              <p className="text-white/85">{item.title}</p>
              {item.remediation && <p className="text-white/45 text-[11px] mt-0.5">{item.remediation}</p>}
            </div>
            <span className="text-[9px] uppercase shrink-0 ml-auto" style={{ color: severityColor(item.severity) }}>{item.severity}</span>
          </li>
        ))}
      </ol>
    </div>
  )
}

function SubdomainInventory({ hosts }) {
  if (!hosts?.length) return null
  return (
    <div className="rounded-2xl border border-white/[0.08] bg-black/40 p-5">
      <p className="text-[10px] font-mono uppercase tracking-widest text-white/40 mb-3">🗂 Subdomain inventory ({hosts.length})</p>
      <div className="flex flex-wrap gap-1.5 max-h-40 overflow-y-auto">
        {hosts.map((h) => (
          <span key={h} className="text-[10px] font-mono px-2 py-1 rounded-lg bg-cyan-500/[0.06] border border-cyan-500/15 text-cyan-200/80">{h}</span>
        ))}
      </div>
    </div>
  )
}

function FindingCard({ f }) {
  const sev = (f.severity || 'info').toLowerCase()
  const asset = ASSET_META[f.asset] ?? { icon: '◆', label: f.asset || 'Finding' }
  return (
    <div className="rounded-xl bg-black/40 border border-white/10 p-3.5 space-y-2 hover:border-white/20 transition-colors">
      <div className="flex items-start justify-between gap-3">
        <div className="flex items-start gap-2 min-w-0">
          <span className="text-base shrink-0 mt-0.5">{asset.icon}</span>
          <div className="min-w-0">
            <p className="text-sm font-semibold text-white/95 leading-snug">{f.title || f.value}</p>
            {f.value && f.value !== f.title && (
              <p className="text-[11px] font-mono text-cyan-300/60 truncate">{f.value}</p>
            )}
          </div>
        </div>
        <span
          className="text-[9px] font-mono px-2 py-0.5 rounded-md border uppercase tracking-wider shrink-0"
          style={{ color: severityColor(sev), borderColor: `${severityColor(sev)}50`, backgroundColor: `${severityColor(sev)}12` }}
        >
          {sev}
        </span>
      </div>
      {f.description && <p className="text-[11px] text-white/55 font-mono leading-relaxed">{f.description}</p>}
      {f.remediation && (
        <p className="text-[11px] text-emerald-300/70 font-mono leading-relaxed">
          <span className="text-emerald-400/90">→ Fix: </span>{f.remediation}
        </p>
      )}
      <div className="flex flex-wrap items-center gap-2 pt-0.5">
        <span className="text-[9px] font-mono px-1.5 py-0.5 rounded bg-white/[0.04] text-white/40 border border-white/[0.06]">{asset.label}</span>
        {f.mitre_attack && (
          <a
            href={`https://attack.mitre.org/techniques/${String(f.mitre_attack).replace('.', '/')}`}
            target="_blank" rel="noopener noreferrer"
            className="text-[9px] font-mono px-1.5 py-0.5 rounded bg-cyan-500/[0.06] text-cyan-300/70 border border-cyan-500/20 hover:text-cyan-200"
          >
            {f.mitre_attack}
          </a>
        )}
      </div>
    </div>
  )
}

// ─── Main page ────────────────────────────────────────────────────────────────

export default function AttackSurfaceManagement() {
  const [clients, setClients] = useState([])
  const [selectedClientId, setSelectedClientId] = useState(null)
  const { postScan } = useCommandCenterScan(selectedClientId)
  const [target, setTarget] = useState('')
  const [params, setParams] = useState(DEFAULT_PARAMS)
  useSyncHubScanParams(ENGINE, params)
  const [showConfig, setShowConfig] = useState(true)
  const [status, setStatus] = useState('idle')
  const [jobId, setJobId] = useState(null)
  const [findings, setFindings] = useState([])
  const [toast, setToast] = useState(null)
  const [assetFilter, setAssetFilter] = useState('all')

  const report = useMemo(
    () => findings.find((f) => f.type === 'attack_surface_report' || f.asset === 'report'),
    [findings],
  )
  const issues = useMemo(
    () => findings.filter((f) => f !== report),
    [findings, report],
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
  } = useWeissmanEnginePage(ENGINE, issues)

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

  useEffect(() => {
    apiFetch('/api/clients')
      .then((r) => (r.ok ? r.json() : []))
      .then((d) => { if (Array.isArray(d)) setClients(d) })
      .catch(() => {})
  }, [])

  useEffect(() => {
    const c = clients.find((x) => String(x.id) === String(selectedClientId))
    const t = firstClientTarget(c)
    if (t) setTarget(t)
  }, [selectedClientId, clients])

  const showToast = useCallback((sev, msg) => {
    const id = Date.now()
    setToast({ id, sev, msg })
    setTimeout(() => setToast((p) => (p?.id === id ? null : p)), 5000)
  }, [])

  const setParam = useCallback((key, val) => setParams((p) => ({ ...p, [key]: val })), [])

  useJobPoll(jobId, {
    enabled: Boolean(jobId),
    onComplete: async (job) => {
      setStatus(uiJobStatus(job.status))
      const f = await resolveJobFindings(job, ENGINE, selectedClientId)
      setFindings(Array.isArray(f) ? f : [])
      setLastUpdated(new Date().toISOString())
      if (job?.id) setLastJobId(String(job.id))
      setJobId(null)
    },
  })

  const handleRun = useCallback(async () => {
    if (!selectedClientId) { showToast('error', 'Select a client first'); return }
    if (!target.trim()) { showToast('error', 'Enter a target domain or IP'); return }
    setStatus('running')
    setFindings([])
    try {
      const body = { engine: ENGINE, client_id: Number(selectedClientId), target: target.trim() }
      for (const [k, v] of Object.entries(params)) {
        if (v === '' || v === null || v === undefined) continue
        body[k] = v
      }
      const { ok, data: d, status } = await postScan(body)
      if (!ok) {
        setStatus('error')
        showToast('error', d.detail || d.error || `Scan failed (${status})`)
        return
      }
      const jid = d.job_id ?? ''
      showToast('info', `Attack-surface scan queued (job ${jid})`)
      if (jid) { setJobId(jid); setShowConfig(false) } else setStatus('error')
    } catch (e) {
      setStatus('error')
      showToast('error', e?.message ?? 'Network error')
    }
  }, [selectedClientId, target, params, showToast])

  const assetTypes = useMemo(() => {
    const s = new Set(issues.map((f) => f.asset).filter(Boolean))
    return ['all', ...Array.from(s)]
  }, [issues])

  const assetFilteredFindings = useMemo(() => {
    if (assetFilter === 'all') return filteredFindings
    return filteredFindings.filter((f) => f.asset === assetFilter)
  }, [filteredFindings, assetFilter])

  const score = report?.surface_score ?? null
  const grade = report?.grade ?? '—'
  const severityCounts = report?.severity_counts ?? {}
  const exposureByAsset = report?.exposure_by_asset ?? {}
  const attackPaths = report?.attack_path_summaries ?? []
  const remediationQueue = report?.remediation_queue ?? []
  const subdomainInventory = report?.subdomain_inventory ?? []

  const handleExport = useCallback(() => {
    if (!report) return
    const blob = new Blob([JSON.stringify({ report, findings: issues }, null, 2)], { type: 'application/json' })
    const url = URL.createObjectURL(blob)
    const a = document.createElement('a')
    a.href = url
    a.download = `easm-${report.host || target || 'scan'}-${Date.now()}.json`
    a.click()
    URL.revokeObjectURL(url)
    showToast('info', 'Exported attack-surface report JSON')
  }, [report, issues, target, showToast])

  const statusBadge = {
    idle: { c: '#6b7280', t: 'Idle' },
    running: { c: '#22d3ee', t: 'Scanning…' },
    completed: { c: '#22c55e', t: 'Completed' },
    error: { c: '#ef4444', t: 'Error' },
  }[status]

  return (
    <PageShell
      hideHubParams
      title="Attack Surface Management"
      badge="EASM"
      badgeColor={ACCENT}
      subtitle="Agentless external attack-surface discovery & continuous exposure scoring — assets, services, TLS/HTTP posture, cloud footprint, and takeover risk."
      actions={(
        <ShellScanActions
          onRefresh={handleRefresh}
          onExport={exportCsv}
          refreshLoading={historyLoading}
          refreshDisabled={status === 'running'}
          exportDisabled={!assetFilteredFindings.length}
        />
      )}
    >
      <AnimatePresence>
        {toast && (
          <motion.div
            key={toast.id}
            initial={{ opacity: 0, y: -8 }} animate={{ opacity: 1, y: 0 }} exit={{ opacity: 0 }}
            className={`fixed top-16 right-4 z-50 rounded-xl border px-4 py-3 text-sm font-mono max-w-sm shadow-2xl backdrop-blur-md ${
              toast.sev === 'error' ? 'bg-rose-950/90 border-rose-500/40 text-rose-200' : 'bg-black/85 border-cyan-500/30 text-cyan-200'
            }`}
          >
            {toast.msg}
          </motion.div>
        )}
      </AnimatePresence>

      {/* ── Control bar ─────────────────────────────────────────────── */}
      <div className="rounded-2xl border border-white/[0.08] bg-black/40 p-4 mb-5">
        <div className="flex flex-wrap items-end gap-3">
          <div className="flex flex-col gap-1">
            <label className="text-[10px] font-mono uppercase tracking-wider text-white/40">Client</label>
            <select
              value={selectedClientId ?? ''}
              onChange={(e) => setSelectedClientId(e.target.value || null)}
              className="bg-black/60 border border-white/10 rounded-lg px-3 py-2 text-sm text-white/85 font-mono focus:outline-none focus:border-cyan-500/40 min-w-[180px]"
            >
              <option value="">Select client…</option>
              {clients.map((c) => <option key={c.id} value={c.id}>{c.name}</option>)}
            </select>
          </div>
          <div className="flex flex-col gap-1 flex-1 min-w-[220px]">
            <label className="text-[10px] font-mono uppercase tracking-wider text-white/40">Target domain / IP</label>
            <input
              type="text" value={target} onChange={(e) => setTarget(e.target.value)}
              placeholder="example.com"
              className="bg-black/60 border border-white/10 rounded-lg px-3 py-2 text-sm text-white/90 font-mono placeholder-white/25 focus:outline-none focus:border-cyan-500/40"
            />
          </div>
          <button
            type="button"
            onClick={() => setShowConfig((s) => !s)}
            className="px-3 py-2 rounded-lg text-xs font-mono border border-white/12 text-white/55 hover:text-white/85 hover:border-white/25 transition-all"
          >
            {showConfig ? '▾ Hide config' : '▸ Scan config'}
          </button>
          <button
            type="button"
            onClick={handleRun}
            disabled={status === 'running' || !selectedClientId}
            className="px-5 py-2 rounded-lg text-sm font-mono font-semibold bg-cyan-500/20 border border-cyan-500/40 text-cyan-200 hover:bg-cyan-500/30 disabled:opacity-40 disabled:cursor-not-allowed transition-all"
          >
            {status === 'running' ? '⟳ Scanning…' : '▶ Map Attack Surface'}
          </button>
          <span className="flex items-center gap-1.5 text-[11px] font-mono" style={{ color: statusBadge.c }}>
            <span className="w-2 h-2 rounded-full" style={{ backgroundColor: statusBadge.c, boxShadow: status === 'running' ? `0 0 6px ${statusBadge.c}` : 'none' }} />
            {statusBadge.t}
          </span>
        </div>

        {/* ── Config panel ──────────────────────────────────────────── */}
        <AnimatePresence>
          {showConfig && (
            <motion.div
              initial={{ opacity: 0, height: 0 }} animate={{ opacity: 1, height: 'auto' }} exit={{ opacity: 0, height: 0 }}
              className="overflow-hidden"
            >
              <div className="mt-4 pt-4 border-t border-white/[0.06] grid grid-cols-1 lg:grid-cols-2 gap-x-8 gap-y-3 max-h-[520px] overflow-y-auto pr-1">
                <div className="space-y-2.5">
                  <p className="text-[10px] font-mono uppercase tracking-widest text-white/35">Modules</p>
                  {TOGGLES.map((tg) => (
                    <div key={tg.key} className="flex items-center justify-between gap-3">
                      <div className="min-w-0">
                        <p className="text-[12px] text-white/80">{tg.label}</p>
                        <p className="text-[10px] font-mono text-white/35">{tg.hint}</p>
                      </div>
                      <Toggle checked={!!params[tg.key]} onChange={(v) => setParam(tg.key, v)} disabled={status === 'running'} />
                    </div>
                  ))}
                </div>
                <div className="space-y-3">
                  <p className="text-[10px] font-mono uppercase tracking-widest text-white/35">Parameters</p>
                  <div className="grid grid-cols-2 gap-3">
                    <Field label="Ports">
                      <input className={inputCls} value={params.ports} onChange={(e) => setParam('ports', e.target.value)}
                        placeholder="top | all | 80,443,8080-8090" />
                    </Field>
                    <Field label="Subdomain sources">
                      <select className={inputCls} value={params.subdomain_sources} onChange={(e) => setParam('subdomain_sources', e.target.value)}>
                        <option value="both">Passive + Brute</option>
                        <option value="passive">Passive (CT)</option>
                        <option value="bruteforce">Brute-force</option>
                      </select>
                    </Field>
                    <Field label="Max subdomains">
                      <input type="number" className={inputCls} value={params.max_subdomains} min={0} max={500}
                        onChange={(e) => setParam('max_subdomains', Number(e.target.value))} />
                    </Field>
                    <Field label="Severity threshold">
                      <select className={inputCls} value={params.severity_threshold} onChange={(e) => setParam('severity_threshold', e.target.value)}>
                        {['info', 'low', 'medium', 'high', 'critical'].map((s) => <option key={s} value={s}>{s}</option>)}
                      </select>
                    </Field>
                    <Field label="Port timeout (ms)">
                      <input type="number" className={inputCls} value={params.port_timeout_ms} min={100} max={5000}
                        onChange={(e) => setParam('port_timeout_ms', Number(e.target.value))} />
                    </Field>
                    <Field label="HTTP timeout (ms)">
                      <input type="number" className={inputCls} value={params.http_timeout_ms} min={1000} max={30000}
                        onChange={(e) => setParam('http_timeout_ms', Number(e.target.value))} />
                    </Field>
                    <Field label="Max findings">
                      <input type="number" className={inputCls} value={params.max_findings} min={1} max={5000}
                        onChange={(e) => setParam('max_findings', Number(e.target.value))} />
                    </Field>
                  </div>
                  <Field label="Custom subdomain wordlist (optional, comma/newline)">
                    <textarea className={`${inputCls} resize-y`} rows={2} value={params.subdomain_wordlist}
                      onChange={(e) => setParam('subdomain_wordlist', e.target.value)}
                      placeholder="api, admin, staging, vpn, …" />
                  </Field>
                </div>
              </div>
            </motion.div>
          )}
        </AnimatePresence>
      </div>

      {/* ── Results ─────────────────────────────────────────────────── */}
      {status === 'running' && findings.length === 0 && (
        <div className="flex items-center justify-center py-20">
          <div className="text-center space-y-3">
            <div className="inline-block h-8 w-8 animate-spin rounded-full border-2 border-cyan-400/30 border-t-cyan-400" />
            <p className="text-sm font-mono text-white/50">Discovering and probing the external attack surface…</p>
          </div>
        </div>
      )}

      {report && (
        <motion.div initial={{ opacity: 0, y: 12 }} animate={{ opacity: 1, y: 0 }} className="space-y-5">
          <div className="flex justify-end">
            <button
              type="button"
              onClick={handleExport}
              className="px-3 py-1.5 rounded-lg text-[11px] font-mono border border-white/15 text-white/60 hover:text-white/90 hover:border-white/30 transition-all"
            >
              ↓ Export JSON
            </button>
          </div>
          {/* Hero */}
          <div className="rounded-2xl border border-white/[0.08] bg-gradient-to-br from-white/[0.06] via-black/40 to-black/60 p-6">
            <div className="flex flex-col md:flex-row items-center gap-6">
              <ScoreRing score={score ?? 0} grade={grade} />
              <div className="flex-1 w-full space-y-3">
                <div>
                  <h2 className="text-lg font-bold text-white">Attack Surface Score — {report.host}</h2>
                  <p className="text-[12px] text-white/50 font-mono">{report.description}</p>
                </div>
                <SeverityBar counts={severityCounts} />
              </div>
            </div>
          </div>

          {/* Metrics */}
          <div className="grid grid-cols-2 lg:grid-cols-4 xl:grid-cols-6 gap-4">
            <MetricCard label="Subdomain assets" value={report.subdomain_count ?? 0} accent="#22d3ee" icon="🗂" />
            <MetricCard label="Exposed services" value={report.exposed_services ?? 0} accent="#f97316" icon="🔌" />
            <MetricCard label="Takeover risks" value={report.takeover_risks ?? 0} accent="#ef4444" icon="🎯" />
            <MetricCard label="Attack paths" value={report.attack_paths ?? 0} accent="#f43f5e" icon="⛓" />
            <MetricCard label="Shadow IT" value={report.shadow_it_signals ?? 0} accent="#a78bfa" icon="👻" />
            <MetricCard label="Service banners" value={report.service_banners ?? 0} accent="#84cc16" icon="📡" />
          </div>

          <AttackPathPanel paths={attackPaths} />
          <RemediationPanel queue={remediationQueue} />
          <SubdomainInventory hosts={subdomainInventory} />

          {/* Exposure by asset */}
          {Object.keys(exposureByAsset).length > 0 && (
            <div className="rounded-2xl border border-white/[0.08] bg-black/40 p-5">
              <p className="text-[10px] font-mono uppercase tracking-widest text-white/40 mb-3">Exposure by category</p>
              <div className="space-y-2">
                {Object.entries(exposureByAsset).sort((a, b) => b[1] - a[1]).map(([asset, n]) => {
                  const max = Math.max(...Object.values(exposureByAsset))
                  const meta = ASSET_META[asset] ?? { icon: '◆', label: asset }
                  return (
                    <div key={asset} className="flex items-center gap-3">
                      <span className="text-[11px] font-mono text-white/60 w-44 shrink-0 truncate">{meta.icon} {meta.label}</span>
                      <div className="flex-1 h-2 rounded-full bg-black/50 overflow-hidden">
                        <div className="h-full rounded-full bg-cyan-500/60" style={{ width: `${(n / max) * 100}%` }} />
                      </div>
                      <span className="text-[11px] font-mono text-white/50 w-8 text-right">{n}</span>
                    </div>
                  )
                })}
              </div>
            </div>
          )}

          {assetTypes.length > 2 && (
            <div className="flex flex-wrap gap-1.5">
              {assetTypes.map((a) => (
                <button key={a} type="button" onClick={() => setAssetFilter(a)}
                  className={`px-2.5 py-1 rounded-lg text-[10px] font-mono border transition-all ${
                    assetFilter === a ? 'text-cyan-200 border-cyan-500/40 bg-cyan-500/10' : 'text-white/45 border-white/[0.08] hover:text-white/70'
                  }`}
                >
                  {a === 'all' ? 'All categories' : `${ASSET_META[a]?.icon ?? '◆'} ${ASSET_META[a]?.label ?? a}`}
                </button>
              ))}
            </div>
          )}

          <WeissmanFindingsPanel
            findings={issues}
            filteredFindings={assetFilteredFindings}
            counts={counts}
            total={issues.length}
            searchQuery={searchQuery}
            onSearchChange={setSearchQuery}
            severityFilter={severityFilter}
            onSeverityChange={setSeverityFilter}
            pending={status === 'running' && issues.length === 0}
            loading={historyLoading && issues.length === 0}
            lastUpdated={lastUpdated}
            jobId={jobId || lastJobId}
            accent={ACCENT}
            showEmptyReady={status !== 'running' && issues.length === 0}
            emptyReadyTitle="Select a client and map its external attack surface."
            emptyReadyBody="Discovers internet-facing assets and scores exposure from real probes."
            renderFinding={(f, i) => <FindingCard key={i} f={f} />}
          />
        </motion.div>
      )}

      {!report && status !== 'running' && (
        <div className="rounded-2xl border border-white/[0.08] bg-black/30 px-6 py-16 text-center">
          <p className="text-4xl mb-3">🛰️</p>
          <p className="text-sm font-mono text-white/50">Select a client and map its external attack surface.</p>
          <p className="text-[11px] font-mono text-white/30 mt-1">Discovers internet-facing assets and scores exposure the way Wiz, Cortex Xpanse & Defender EASM do — from real probes.</p>
        </div>
      )}
    </PageShell>
  )
}

const inputCls = 'w-full bg-black/60 border border-white/10 rounded-lg px-2.5 py-1.5 text-[12px] text-white/90 font-mono placeholder-white/25 focus:outline-none focus:border-cyan-500/40'

function Field({ label, children }) {
  return (
    <div className="flex flex-col gap-1">
      <label className="text-[10px] font-mono uppercase tracking-wider text-white/40">{label}</label>
      {children}
    </div>
  )
}
