import { useCommandCenterScan } from '../hooks/useCommandCenterScan'
import { useSyncHubScanParams, useHubEngineFocus } from '../hooks/useLaunchEngineScan'
import { useClientTargetPrefill } from '../hooks/useHubLocalScanParams'
import React, { useState, useEffect, useCallback, useMemo } from 'react'
import { Link } from 'react-router-dom'
import { useTranslation } from 'react-i18next'
import { motion, AnimatePresence } from 'framer-motion'
import PageShell from './PageShell'
import ShellScanActions from '../components/engine/ShellScanActions'
import WeissmanFindingsPanel from '../components/engine/WeissmanFindingsPanel'
import { useWeissmanEnginePage, applyHistoryFindings } from '../hooks/useWeissmanEnginePage'
import { apiFetch } from '../lib/apiBase'
import { useJobPoll, resolveJobFindings, extractFindingsFromJob, uiJobStatus } from '../lib/useJobPoll'

const FLAGSHIP_ID = 'bgp_dns_hijacking'

const OTHER_ENGINES = [
  {
    id: 'ipv6_attack',
    label: 'IPv6 Attack Surface',
    description: 'AAAA record enumeration, link-local leak, router advertisement flood surface',
    mitre: 'T1018',
  },
  {
    id: 'mtls_grpc',
    label: 'Transport Security (TLS/mTLS/gRPC)',
    description: 'World-class transport posture — weak-crypto matrix, gRPC/gRPC-Web/Connect, mTLS, chain trust, h2c, HTTP/3, DANE/CAA/CT shadow hosts, attack paths & 0–100 grade',
    mitre: 'T1557',
    commandCenter: '/transport-security',
  },
  {
    id: 'smb_netbios',
    label: 'SMB / NetBIOS',
    description: 'Live SMB2/3 protocol assessment: signing, encryption, SMBv1/EternalBlue, SMBGhost, anonymous IPC$/RPC pipes, NTLM/SPNEGO fingerprint, NetBIOS DC role',
    mitre: 'T1021.002',
    commandCenter: '/smb-netbios',
  },
]

// Full default knob surface — mirrors every parameter the backend ArsenalConfig reads.
const DEFAULT_PARAMS = {
  resolvers: '',
  check_resolver_consensus: true,
  check_dnssec: true,
  check_rpki: true,
  check_bgp: true,
  check_caa: true,
  check_ns: true,
  check_takeover: true,
  check_aaaa: false,
  check_tls_identity: true,
  check_bogon: true,
  check_ttl: true,
  check_routing_history: true,
  check_dane: true,
  check_ct: true,
  check_auth_recursive: true,
  check_rdap: true,
  check_irr: true,
  check_more_specific: true,
  check_dual_stack: true,
  check_soa: true,
  check_baseline_delta: true,
  check_caa_ct_cross: true,
  check_rpki_maxlength: true,
  check_hsts: true,
  check_http_redirect: true,
  check_mx_origin: true,
  check_glue: true,
  check_bgp_visibility: true,
  check_geo: false,
  check_dnssec_ad_divergence: true,
  check_fcrdns: true,
  check_expected_ips: false,
  check_cname_chain: true,
  check_spf_apex: true,
  check_wildcard: true,
  check_ns_lame: true,
  check_cds_cdnskey: true,
  check_orphan_ds: true,
  check_resolver_timing: true,
  autonomous_mode: true,
  force_all_probes: false,
  use_static_subdomain_wordlist: false,
  check_ct_discovery: true,
  check_delegation_walk: true,
  check_udp_doh_cross: true,
  check_dmarc: true,
  check_parent_ns: true,
  max_ct_hosts: '32',
  expected_countries: '',
  expected_a_ips: '',
  resolver_timing_factor: '3',
  low_ttl_threshold_secs: '300',
  expected_origin_asns: '',
  subdomains: '',
  ripe_base: 'https://stat.ripe.net',
  timeout_ms: '8000',
  concurrency: '8',
  intensity: 'normal',
}

const INTENSITIES = ['light', 'normal', 'aggressive']

const splitCsv = (s) => String(s || '').split(/[\n,\s;]+/).map((x) => x.trim()).filter(Boolean)
const numOr = (v, d) => {
  const n = Number(v)
  return Number.isFinite(n) ? n : d
}

function buildBgpBody(params, clientId, target) {
  const body = {
    engine: FLAGSHIP_ID,
    client_id: Number(clientId),
    target: (target || '').trim(),
    timeout: 300,
    check_resolver_consensus: !!params.check_resolver_consensus,
    check_dnssec: !!params.check_dnssec,
    check_rpki: !!params.check_rpki,
    check_bgp: !!params.check_bgp,
    check_caa: !!params.check_caa,
    check_ns: !!params.check_ns,
    check_takeover: !!params.check_takeover,
    check_aaaa: !!params.check_aaaa,
    check_tls_identity: !!params.check_tls_identity,
    check_bogon: !!params.check_bogon,
    check_ttl: !!params.check_ttl,
    check_routing_history: !!params.check_routing_history,
    check_dane: !!params.check_dane,
    check_ct: !!params.check_ct,
    check_auth_recursive: !!params.check_auth_recursive,
    check_rdap: !!params.check_rdap,
    check_irr: !!params.check_irr,
    check_more_specific: !!params.check_more_specific,
    check_dual_stack: !!params.check_dual_stack,
    check_soa: !!params.check_soa,
    check_baseline_delta: !!params.check_baseline_delta,
    check_caa_ct_cross: !!params.check_caa_ct_cross,
    check_rpki_maxlength: !!params.check_rpki_maxlength,
    check_hsts: !!params.check_hsts,
    check_http_redirect: !!params.check_http_redirect,
    check_mx_origin: !!params.check_mx_origin,
    check_glue: !!params.check_glue,
    check_bgp_visibility: !!params.check_bgp_visibility,
    check_geo: !!params.check_geo,
    check_dnssec_ad_divergence: !!params.check_dnssec_ad_divergence,
    check_fcrdns: !!params.check_fcrdns,
    check_expected_ips: !!params.check_expected_ips,
    check_cname_chain: !!params.check_cname_chain,
    check_spf_apex: !!params.check_spf_apex,
    check_wildcard: !!params.check_wildcard,
    check_ns_lame: !!params.check_ns_lame,
    check_cds_cdnskey: !!params.check_cds_cdnskey,
    check_orphan_ds: !!params.check_orphan_ds,
    check_resolver_timing: !!params.check_resolver_timing,
    autonomous_mode: !!params.autonomous_mode,
    force_all_probes: !!params.force_all_probes,
    use_static_subdomain_wordlist: !!params.use_static_subdomain_wordlist,
    check_ct_discovery: !!params.check_ct_discovery,
    check_delegation_walk: !!params.check_delegation_walk,
    check_udp_doh_cross: !!params.check_udp_doh_cross,
    check_dmarc: !!params.check_dmarc,
    check_parent_ns: !!params.check_parent_ns,
    max_ct_hosts: numOr(params.max_ct_hosts, 32),
    low_ttl_threshold_secs: numOr(params.low_ttl_threshold_secs, 300),
    resolver_timing_factor: numOr(params.resolver_timing_factor, 3),
    timeout_ms: numOr(params.timeout_ms, 8000),
    concurrency: numOr(params.concurrency, 8),
    intensity: params.intensity,
  }
  const resolvers = splitCsv(params.resolvers)
  if (resolvers.length) body.resolvers = resolvers
  const asns = splitCsv(params.expected_origin_asns)
  if (asns.length) body.expected_origin_asns = asns
  const subs = splitCsv(params.subdomains)
  if (params.use_static_subdomain_wordlist && subs.length) body.subdomains = subs
  const countries = splitCsv(params.expected_countries).map((c) => c.toUpperCase()).filter((c) => c.length === 2)
  if (countries.length) body.expected_countries = countries
  const aips = splitCsv(params.expected_a_ips)
  if (aips.length) body.expected_a_ips = aips
  if (params.ripe_base.trim() && params.ripe_base.trim() !== DEFAULT_PARAMS.ripe_base) body.ripe_base = params.ripe_base.trim()
  return body
}

// ─── Reusable control primitives ─────────────────────────────────────────────

function Section({ title, icon, accent = '#f97316', defaultOpen = true, children }) {
  const [open, setOpen] = useState(defaultOpen)
  return (
    <div className="rounded-xl border bg-[var(--table-surface)] overflow-hidden" style={{ borderColor: `${accent}22` }}>
      <button
        type="button"
        onClick={() => setOpen((o) => !o)}
        className="w-full flex items-center justify-between px-3 py-2.5 hover:bg-[var(--row-hover-bg)] transition-colors"
      >
        <span className="flex items-center gap-2 text-[11px] font-mono uppercase tracking-[0.18em] font-semibold" style={{ color: accent }}>
          <span>{icon}</span>{title}
        </span>
        <span className={`text-[var(--text-muted)] text-xs transition-transform ${open ? 'rotate-90' : ''}`}>▶</span>
      </button>
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

function TextField({ label, hint, value, onChange, placeholder, area = false }) {
  const cls = 'w-full bg-[var(--scrim)] border border-[var(--border-default)] rounded-lg px-2.5 py-1.5 text-xs text-[var(--text-primary)] font-mono focus:outline-none focus:border-[#f97316]/40'
  return (
    <FieldRow label={label} hint={hint}>
      {area
        ? <textarea rows={2} value={value} placeholder={placeholder} onChange={(e) => onChange(e.target.value)} className={`${cls} resize-y`} />
        : <input type="text" value={value} placeholder={placeholder} onChange={(e) => onChange(e.target.value)} className={cls} />}
    </FieldRow>
  )
}

function NumField({ label, hint, value, onChange, min, max }) {
  return (
    <FieldRow label={label} hint={hint}>
      <input type="number" value={value} min={min} max={max} onChange={(e) => onChange(e.target.value)}
        className="w-full bg-[var(--scrim)] border border-[var(--border-default)] rounded-lg px-2.5 py-1.5 text-xs text-[var(--text-primary)] font-mono focus:outline-none focus:border-[#f97316]/40" />
    </FieldRow>
  )
}

function SelectField({ label, value, onChange, options }) {
  return (
    <FieldRow label={label}>
      <select value={value} onChange={(e) => onChange(e.target.value)}
        className="w-full bg-[var(--scrim)] border border-[var(--border-default)] rounded-lg px-2.5 py-1.5 text-xs text-[var(--text-primary)] font-mono focus:outline-none focus:border-[#f97316]/40">
        {options.map((o) => <option key={o.value} value={o.value}>{o.label}</option>)}
      </select>
    </FieldRow>
  )
}

function Toggle({ label, value, onChange }) {
  return (
    <button type="button" onClick={() => onChange(!value)}
      className={`flex items-center justify-between w-full px-2.5 py-1.5 rounded-lg border text-[11px] font-mono transition-all ${
        value ? 'border-[#f97316]/40 bg-[#f97316]/10 text-[#f97316]' : 'border-[var(--border-default)] bg-[var(--bg-2)] text-[var(--text-muted)] hover:text-[var(--text-tertiary)]'}`}>
      <span>{label}</span>
      <span className={`w-7 h-4 rounded-full relative transition-colors ${value ? 'bg-[#f97316]/40' : 'bg-[var(--row-hover-bg)]'}`}>
        <span className={`absolute top-0.5 w-3 h-3 rounded-full bg-white transition-all ${value ? 'left-3.5' : 'left-0.5'}`} />
      </span>
    </button>
  )
}

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
    <div className="relative flex items-center justify-center w-[140px] h-[140px] shrink-0">
      <svg width="140" height="140" className="-rotate-90">
        <circle cx="70" cy="70" r={r} fill="none" stroke="rgba(255,255,255,0.08)" strokeWidth="10" />
        <motion.circle cx="70" cy="70" r={r} fill="none" stroke={c} strokeWidth="10" strokeLinecap="round"
          initial={{ strokeDasharray: `0 ${circ}` }} animate={{ strokeDasharray: `${dash} ${circ}` }}
          transition={{ duration: 0.9, ease: 'easeOut' }} style={{ filter: `drop-shadow(0 0 6px ${c}80)` }} />
      </svg>
      <div className="absolute inset-0 flex flex-col items-center justify-center">
        <span className="text-4xl font-bold font-mono" style={{ color: c }}>{score}</span>
        <span className="text-[9px] font-mono text-[var(--text-muted)] uppercase tracking-widest">{label}</span>
      </div>
    </div>
  )
}

function PostureChip({ label, state }) {
  const styles = {
    good: 'text-[#4ade80] bg-[#4ade80]/10 border-[#4ade80]/30',
    bad: 'text-red-300 bg-red-950/30 border-red-500/30',
    warn: 'text-amber-300 bg-amber-950/20 border-amber-500/30',
    na: 'text-[var(--text-disabled)] bg-[var(--row-hover-bg)] border-[var(--border-default)]',
  }[state] ?? 'text-[var(--text-disabled)] bg-[var(--row-hover-bg)] border-[var(--border-default)]'
  const glyph = { good: '✓', bad: '✕', warn: '!', na: '–' }[state] ?? '–'
  return (
    <div className={`flex items-center gap-2 px-2.5 py-1.5 rounded-lg border text-[10px] font-mono ${styles}`}>
      <span className="font-bold">{glyph}</span><span>{label}</span>
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
      <button type="button" onClick={() => setOpen((o) => !o)} className="w-full flex items-start gap-2 px-3 py-2 text-left hover:bg-[var(--row-hover-bg)]">
        <span className="text-[8px] font-mono uppercase tracking-widest px-1.5 py-0.5 rounded border border-current shrink-0 mt-0.5">{sev}</span>
        <span className="text-[11px] font-mono text-[var(--text-primary)] flex-1 leading-snug">{f.title || f.type}</span>
        {typeof f.confidence === 'number' && <span className="text-[9px] font-mono text-[var(--text-disabled)] shrink-0">{Math.round(f.confidence * 100)}%</span>}
        <span className={`text-[var(--text-disabled)] text-[10px] transition-transform ${open ? 'rotate-90' : ''}`}>▶</span>
      </button>
      {open && (
        <div className="px-3 pb-3 pt-1 space-y-2 border-t border-[var(--border-subtle)]">
          {f.description && <p className="text-[10px] font-mono text-[var(--text-tertiary)] leading-relaxed">{f.description}</p>}
          {f.remediation && <p className="text-[10px] font-mono text-[#f97316]/70 leading-relaxed"><span className="text-[var(--text-disabled)]">→ </span>{f.remediation}</p>}
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

function StatusBadge({ status, t }) {
  const map = {
    running: { label: t('pages.networkIntelligence.status_running'), cls: 'text-[#22d3ee] border-[#22d3ee]/30 bg-[#22d3ee]/10' },
    completed: { label: t('pages.networkIntelligence.status_done'), cls: 'text-[#4ade80] border-[#4ade80]/30 bg-[#4ade80]/10' },
    error: { label: t('pages.networkIntelligence.status_error'), cls: 'text-red-400 border-red-500/30 bg-red-950/30' },
    idle: { label: t('pages.networkIntelligence.status_idle'), cls: 'text-[var(--text-disabled)] border-[var(--border-default)] bg-[var(--row-hover-bg)]' },
  }
  const { label, cls } = map[status] ?? map.idle
  return <span className={`text-[9px] font-mono px-1.5 py-0.5 rounded border uppercase tracking-widest ${cls}`}>{label}</span>
}

// ─── Flagship: BGP/DNS Hijack-Resistance ─────────────────────────────────────

function BgpDnsFlagship({ clientId, target, showToast, t, tt, onShellReady, isFocused, onFocus }) {
  const { postScan } = useCommandCenterScan(clientId)
  useHubEngineFocus(FLAGSHIP_ID, { active: isFocused })
  const [params, setParams] = useState(DEFAULT_PARAMS)
  useSyncHubScanParams(FLAGSHIP_ID, params)
  const [findings, setFindings] = useState([])
  const [scanning, setScanning] = useState(false)
  const [pendingJobId, setPendingJobId] = useState(null)
  const setParam = useCallback((k, v) => setParams((p) => ({ ...p, [k]: v })), [])

  const summary = useMemo(() => findings.find((f) => f.type === 'dns_bgp_integrity_summary') ?? null, [findings])
  const sorted = useMemo(
    () => [...findings]
      .filter((f) => f.type !== 'dns_bgp_integrity_summary')
      .sort((a, b) => (SEV_RANK[String(b.severity).toLowerCase()] ?? 0) - (SEV_RANK[String(a.severity).toLowerCase()] ?? 0)),
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
  } = useWeissmanEnginePage(FLAGSHIP_ID, sorted)

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
    onShellReady?.({
      onRefresh: handleRefresh,
      onExport: exportCsv,
      refreshLoading: historyLoading,
      refreshDisabled: scanning,
      exportDisabled: !filteredFindings.length,
    })
  }, [onShellReady, handleRefresh, exportCsv, historyLoading, scanning, filteredFindings.length])

  useJobPoll(pendingJobId, {
    enabled: Boolean(pendingJobId),
    onComplete: async (job) => {
      const resolved = await resolveJobFindings(job, FLAGSHIP_ID, clientId)
      const fromJob = extractFindingsFromJob(job)
      setFindings(resolved.length ? resolved : fromJob)
      setLastUpdated(new Date().toISOString())
      if (job?.id) setLastJobId(String(job.id))
      setScanning(false)
      setPendingJobId(null)
    },
  })

  const handleScan = useCallback(async () => {
    if (!clientId) { showToast('error', t('pages.networkIntelligence.select_client_first')); return }
    if (!target.trim()) { showToast('error', tt('target_required', 'A target host is required')); return }
    setScanning(true)
    setFindings([])
    try {
      const { ok, data: d, status } = await postScan(buildBgpBody(params, clientId, target))
      if (!ok) { setScanning(false); showToast('error', d.detail || t('pages.networkIntelligence.scan_failed')); return }
      const jobId = d.job_id ?? ''
      showToast('info', t('pages.networkIntelligence.queued', { label: 'BGP/DNS', jobId }))
      if (jobId) setPendingJobId(jobId); else setScanning(false)
    } catch (e) {
      setScanning(false)
      showToast('error', e?.message ?? t('pages.networkIntelligence.scan_failed'))
    }
  }, [clientId, target, params, postScan, showToast, t, tt])

  const score = summary ? Number(summary.hijack_resistance_score ?? 0) : null
  const ev = summary?.evidence ?? {}
  const rpkiState = ev.rpki_invalid ? 'bad' : (ev.rpki_valid ? 'good' : 'warn')

  return (
    <motion.div initial={{ opacity: 0, y: 8 }} animate={{ opacity: 1, y: 0 }}
      onMouseEnter={onFocus}
      onFocus={onFocus}
      className="rounded-2xl bg-gradient-to-br from-[#f97316]/10 to-black/40 backdrop-blur-md border border-[#f97316]/20 p-6">
      <div className="flex items-start justify-between gap-4 mb-5 flex-wrap">
        <div>
          <div className="flex items-center gap-2">
            <span className="text-2xl">🛰</span>
            <h2 className="text-base font-bold text-white">{tt('flagship_title', 'DNS & BGP Hijack-Resistance')}</h2>
          </div>
          <p className="text-[11px] text-[var(--text-muted)] mt-1 max-w-2xl leading-relaxed">
            {tt('flagship_desc', 'Live multi-resolver consensus, DNSSEC chain validation, RPKI ROA validation, BGP origin-AS / MOAS analysis, NS diversity, CAA & subdomain-takeover — fully read-only.')}
          </p>
        </div>
        <button type="button" onClick={handleScan} disabled={scanning || !clientId}
          className="shrink-0 px-5 py-2 rounded-xl font-mono text-sm border border-[#f97316]/40 text-[#f97316] bg-[#f97316]/10 hover:bg-[#f97316]/20 disabled:opacity-40 disabled:cursor-not-allowed transition-all">
          {scanning ? tt('scanning', '⟳ Scanning…') : tt('run_scan', '▶ Run Hijack-Resistance Scan')}
        </button>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-5">
        {/* Parameter column */}
        <div className="space-y-3 lg:col-span-1">
          <div className="flex items-center justify-between">
            <h3 className="text-[11px] font-mono text-[var(--text-muted)] uppercase tracking-widest">{tt('params', 'Parameters')}</h3>
            <button type="button" onClick={() => setParams(DEFAULT_PARAMS)} className="text-[9px] font-mono text-[var(--text-disabled)] hover:text-[var(--text-tertiary)] underline">{tt('reset', 'reset')}</button>
          </div>
          <Section title={tt('sec_probes', 'Probes')} icon="⚡">
            <Toggle label={tt('p_consensus', 'Multi-resolver consensus')} value={params.check_resolver_consensus} onChange={(v) => setParam('check_resolver_consensus', v)} />
            <Toggle label={tt('p_dnssec', 'DNSSEC validation')} value={params.check_dnssec} onChange={(v) => setParam('check_dnssec', v)} />
            <Toggle label={tt('p_rpki', 'RPKI ROA validation')} value={params.check_rpki} onChange={(v) => setParam('check_rpki', v)} />
            <Toggle label={tt('p_bgp', 'BGP origin / MOAS')} value={params.check_bgp} onChange={(v) => setParam('check_bgp', v)} />
            <Toggle label={tt('p_caa', 'CAA issuance control')} value={params.check_caa} onChange={(v) => setParam('check_caa', v)} />
            <Toggle label={tt('p_ns', 'NS diversity')} value={params.check_ns} onChange={(v) => setParam('check_ns', v)} />
            <Toggle label={tt('p_takeover', 'Subdomain takeover')} value={params.check_takeover} onChange={(v) => setParam('check_takeover', v)} />
            <Toggle label={tt('p_aaaa', 'IPv6 (AAAA) records')} value={params.check_aaaa} onChange={(v) => setParam('check_aaaa', v)} />
            <Toggle label={tt('p_tls', 'TLS identity binding')} value={params.check_tls_identity} onChange={(v) => setParam('check_tls_identity', v)} />
            <Toggle label={tt('p_bogon', 'Bogon / martian IP')} value={params.check_bogon} onChange={(v) => setParam('check_bogon', v)} />
            <Toggle label={tt('p_ttl', 'Low-TTL signal')} value={params.check_ttl} onChange={(v) => setParam('check_ttl', v)} />
            <Toggle label={tt('p_routing_hist', 'BGP routing-history')} value={params.check_routing_history} onChange={(v) => setParam('check_routing_history', v)} />
            <Toggle label={tt('p_dane', 'DANE / TLSA')} value={params.check_dane} onChange={(v) => setParam('check_dane', v)} />
            <Toggle label={tt('p_ct', 'CT inventory (crt.sh)')} value={params.check_ct} onChange={(v) => setParam('check_ct', v)} />
            <Toggle label={tt('p_auth_recursive', 'Auth vs recursive DNS')} value={params.check_auth_recursive} onChange={(v) => setParam('check_auth_recursive', v)} />
            <Toggle label={tt('p_rdap', 'RDAP registrar lock')} value={params.check_rdap} onChange={(v) => setParam('check_rdap', v)} />
            <Toggle label={tt('p_irr', 'IRR vs BGP')} value={params.check_irr} onChange={(v) => setParam('check_irr', v)} />
            <Toggle label={tt('p_more_specific', 'More-specific hijack')} value={params.check_more_specific} onChange={(v) => setParam('check_more_specific', v)} />
            <Toggle label={tt('p_dual_stack', 'IPv4/IPv6 origin bind')} value={params.check_dual_stack} onChange={(v) => setParam('check_dual_stack', v)} />
            <Toggle label={tt('p_soa', 'SOA integrity')} value={params.check_soa} onChange={(v) => setParam('check_soa', v)} />
            <Toggle label={tt('p_baseline', 'Baseline delta')} value={params.check_baseline_delta} onChange={(v) => setParam('check_baseline_delta', v)} />
            <Toggle label={tt('p_caa_ct', 'CAA⟷CT cross-check')} value={params.check_caa_ct_cross} onChange={(v) => setParam('check_caa_ct_cross', v)} />
            <Toggle label={tt('p_hsts', 'HSTS')} value={params.check_hsts} onChange={(v) => setParam('check_hsts', v)} />
            <Toggle label={tt('p_redirect', 'HTTP redirect bind')} value={params.check_http_redirect} onChange={(v) => setParam('check_http_redirect', v)} />
            <Toggle label={tt('p_mx', 'MX origin bind')} value={params.check_mx_origin} onChange={(v) => setParam('check_mx_origin', v)} />
            <Toggle label={tt('p_glue', 'NS glue')} value={params.check_glue} onChange={(v) => setParam('check_glue', v)} />
            <Toggle label={tt('p_visibility', 'BGP visibility')} value={params.check_bgp_visibility} onChange={(v) => setParam('check_bgp_visibility', v)} />
            <Toggle label={tt('p_geo', 'Geo country bind')} value={params.check_geo} onChange={(v) => setParam('check_geo', v)} />
            <Toggle label={tt('p_ad_divergence', 'DNSSEC AD divergence')} value={params.check_dnssec_ad_divergence} onChange={(v) => setParam('check_dnssec_ad_divergence', v)} />
            <Toggle label={tt('p_fcrdns', 'FCrDNS')} value={params.check_fcrdns} onChange={(v) => setParam('check_fcrdns', v)} />
            <Toggle label={tt('p_expected_ips', 'Expected A IPs')} value={params.check_expected_ips} onChange={(v) => setParam('check_expected_ips', v)} />
            <Toggle label={tt('p_cname', 'CNAME chain audit')} value={params.check_cname_chain} onChange={(v) => setParam('check_cname_chain', v)} />
            <Toggle label={tt('p_spf', 'SPF at apex')} value={params.check_spf_apex} onChange={(v) => setParam('check_spf_apex', v)} />
            <Toggle label={tt('p_wildcard', 'Wildcard DNS probe')} value={params.check_wildcard} onChange={(v) => setParam('check_wildcard', v)} />
            <Toggle label={tt('p_ns_lame', 'Lame delegation')} value={params.check_ns_lame} onChange={(v) => setParam('check_ns_lame', v)} />
            <Toggle label={tt('p_cds', 'CDS/CDNSKEY')} value={params.check_cds_cdnskey} onChange={(v) => setParam('check_cds_cdnskey', v)} />
            <Toggle label={tt('p_orphan_ds', 'Orphan DS')} value={params.check_orphan_ds} onChange={(v) => setParam('check_orphan_ds', v)} />
            <Toggle label={tt('p_timing', 'Resolver timing')} value={params.check_resolver_timing} onChange={(v) => setParam('check_resolver_timing', v)} />
            <Toggle label={tt('p_autonomous', 'Autonomous discovery (v7)')} value={params.autonomous_mode} onChange={(v) => setParam('autonomous_mode', v)} />
            <Toggle label={tt('p_ct_discovery', 'CT host discovery')} value={params.check_ct_discovery} onChange={(v) => setParam('check_ct_discovery', v)} />
            <Toggle label={tt('p_delegation', 'Delegation walk')} value={params.check_delegation_walk} onChange={(v) => setParam('check_delegation_walk', v)} />
            <Toggle label={tt('p_udp_doh', 'UDP/DoH cross-check')} value={params.check_udp_doh_cross} onChange={(v) => setParam('check_udp_doh_cross', v)} />
            <Toggle label={tt('p_dmarc', 'DMARC')} value={params.check_dmarc} onChange={(v) => setParam('check_dmarc', v)} />
            <Toggle label={tt('p_parent_ns', 'Parent NS consistency')} value={params.check_parent_ns} onChange={(v) => setParam('check_parent_ns', v)} />
          </Section>
          <Section title={tt('sec_bgp', 'BGP / Origin')} icon="⌖" accent="#a855f7">
            <TextField label={tt('expected_asns', 'Expected origin ASNs')} hint={tt('expected_asns_hint', 'Allow-list, e.g. AS13335, 15169. Any other origin → hijack alert.')} value={params.expected_origin_asns} onChange={(v) => setParam('expected_origin_asns', v)} placeholder="AS13335, 15169" />
            <TextField label={tt('expected_a_ips', 'Expected A IPs')} hint={tt('expected_a_ips_hint', 'Enable check_expected_ips — e.g. 203.0.113.10')} value={params.expected_a_ips} onChange={(v) => setParam('expected_a_ips', v)} placeholder="203.0.113.10, 203.0.113.11" />
            <TextField label={tt('expected_countries', 'Expected countries (ISO-2)')} hint={tt('expected_countries_hint', 'Enable geo check — e.g. US, IL')} value={params.expected_countries} onChange={(v) => setParam('expected_countries', v)} placeholder="US, IL" />
            <TextField label={tt('ripe_base', 'RIPEstat base URL')} value={params.ripe_base} onChange={(v) => setParam('ripe_base', v)} placeholder="https://stat.ripe.net" />
          </Section>
          <Section title={tt('sec_scope', 'Resolvers & Scope')} icon="◎" accent="#22d3ee" defaultOpen={false}>
            <TextField area label={tt('resolvers', 'DoH resolvers')} hint={tt('resolvers_hint', 'One per line: Name=https://host/dns-query. Empty = Cloudflare+Google+Quad9.')} value={params.resolvers} onChange={(v) => setParam('resolvers', v)} placeholder="Cloudflare=https://cloudflare-dns.com/dns-query" />
            <TextField area label={tt('subdomains', 'Extra subdomains')} hint={tt('subdomains_hint', 'Also checked for dangling-CNAME takeover.')} value={params.subdomains} onChange={(v) => setParam('subdomains', v)} placeholder="www, api, mail" />
          </Section>
          <Section title={tt('sec_transport', 'Transport')} icon="⇄" accent="#64748b" defaultOpen={false}>
            <NumField label={tt('timeout_ms', 'Per-probe timeout (ms)')} value={params.timeout_ms} onChange={(v) => setParam('timeout_ms', v)} min={500} max={30000} />
            <NumField label={tt('concurrency', 'Concurrency')} value={params.concurrency} onChange={(v) => setParam('concurrency', v)} min={1} max={16} />
            <NumField label={tt('low_ttl_secs', 'Low-TTL threshold (s)')} value={params.low_ttl_threshold_secs} onChange={(v) => setParam('low_ttl_threshold_secs', v)} min={30} max={86400} />
            <NumField label={tt('timing_factor', 'Resolver timing factor (×)')} value={params.resolver_timing_factor} onChange={(v) => setParam('resolver_timing_factor', v)} min={1.5} max={10} />
            <SelectField label={tt('intensity', 'Intensity')} value={params.intensity} onChange={(v) => setParam('intensity', v)} options={INTENSITIES.map((i) => ({ value: i, label: tt(`intensity_${i}`, i) }))} />
          </Section>
        </div>

        {/* Results column */}
        <div className="space-y-4 lg:col-span-2">
          <AnimatePresence mode="wait">
            {summary ? (
              <motion.div key="score" initial={{ opacity: 0, y: 8 }} animate={{ opacity: 1, y: 0 }} className="rounded-2xl bg-[var(--bg-2)] border border-[var(--border-default)] p-5">
                <div className="flex items-center gap-6 flex-wrap">
                  <ScoreGauge score={score ?? 0} label={tt('score_label', 'RESISTANCE')} />
                  <div className="flex-1 min-w-[240px] space-y-3">
                    <p className="text-[11px] font-mono text-[var(--text-muted)] leading-relaxed">{summary.description}</p>
                    <div className="grid grid-cols-2 gap-2">
                      <PostureChip label={tt('po_dnssec', 'DNSSEC')} state={ev.dnssec_broken ? 'bad' : (ev.dnssec_validated ? 'good' : 'warn')} />
                      <PostureChip label={tt('po_rpki', 'RPKI ROA')} state={rpkiState} />
                      <PostureChip label={tt('po_auth', 'Auth=recursive')} state={ev.auth_recursive_match ? 'good' : (ev.auth_recursive_match === false ? 'bad' : 'warn')} />
                      <PostureChip label={tt('po_rdap', 'RDAP lock')} state={ev.rdap_transfer_locked ? 'good' : 'warn'} />
                      <PostureChip label={tt('po_irr', 'IRR=BGP')} state={ev.irr_matches_bgp ? 'good' : 'bad'} />
                      <PostureChip label={tt('po_consensus', 'Resolver consensus')} state={ev.resolver_consensus ? 'good' : 'bad'} />
                      <PostureChip label={tt('po_tls', 'TLS bind')} state={ev.tls_identity_match ? 'good' : (ev.tls_identity_match === false ? 'bad' : 'warn')} />
                      <PostureChip label={tt('po_bogon', 'Bogon-free')} state={ev.bogon_free ? 'good' : 'bad'} />
                      <PostureChip label={tt('po_caa', 'CAA')} state={ev.caa_present ? 'good' : 'warn'} />
                      <PostureChip label={tt('po_ns', 'NS diversity')} state={ev.ns_diverse ? 'good' : 'warn'} />
                      <PostureChip label={tt('po_origin', 'BGP origin')} state={ev.unexpected_origin ? 'bad' : (ev.moas ? 'warn' : 'good')} />
                    </div>
                  </div>
                </div>
                {Array.isArray(summary.roadmap) && summary.roadmap.length > 0 && (
                  <div className="mt-4 pt-3 border-t border-[var(--border-subtle)]">
                    <h4 className="text-[10px] font-mono text-[var(--text-muted)] uppercase tracking-widest mb-2">{tt('roadmap', 'Hardening Roadmap')}</h4>
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
              <motion.div key="empty" initial={{ opacity: 0 }} animate={{ opacity: 1 }} className="rounded-2xl bg-[var(--bg-2)] border border-[var(--border-default)] p-10 text-center">
                <p className="text-[11px] font-mono text-[var(--text-disabled)]">
                  {scanning ? tt('scan_running', 'Probing DNS resolvers, DNSSEC, RPKI and BGP origins…')
                    : !clientId ? t('pages.networkIntelligence.select_client_warning')
                      : tt('empty_ready', 'Ready — run to measure DNS/BGP hijack resistance.')}
                </p>
              </motion.div>
            )}
          </AnimatePresence>
          <WeissmanFindingsPanel
            findings={sorted}
            filteredFindings={filteredFindings}
            counts={counts}
            total={sorted.length}
            searchQuery={searchQuery}
            onSearchChange={setSearchQuery}
            severityFilter={severityFilter}
            onSeverityChange={setSeverityFilter}
            pending={scanning && sorted.length === 0}
            loading={historyLoading && sorted.length === 0}
            lastUpdated={lastUpdated}
            jobId={pendingJobId || lastJobId}
            accent="#f97316"
            title={tt('findings', 'Findings')}
            showEmptyReady={!scanning && sorted.length === 0}
            emptyReadyTitle={tt('empty_ready', 'Ready — run to measure DNS/BGP hijack resistance.')}
            emptyReadyBody={tt('empty_no_findings', 'No exposures returned — hijack-resistance posture appears strong.')}
            renderFinding={(f, i) => <FindingCard key={i} f={f} />}
          />
        </div>
      </div>
    </motion.div>
  )
}

// ─── Secondary network engine cards ──────────────────────────────────────────

function NetworkEngineCard({ engine, clientId, target, showToast, isFocused, onFocus, t }) {
  const { postScan } = useCommandCenterScan(clientId)
  useHubEngineFocus(engine.id, { active: isFocused })
  const [status, setStatus] = useState('idle')
  const [findings, setFindings] = useState([])
  const [lastRun, setLastRun] = useState(null)
  const [pendingJobId, setPendingJobId] = useState(null)

  useJobPoll(pendingJobId, {
    enabled: Boolean(pendingJobId),
    onComplete: async (job) => {
      setStatus(uiJobStatus(job.status))
      setLastRun(new Date().toLocaleTimeString())
      setFindings(await resolveJobFindings(job, engine.id, clientId))
      setPendingJobId(null)
    },
  })

  const handleRun = useCallback(async () => {
    if (!clientId) { showToast('error', t('pages.networkIntelligence.select_client_first')); return }
    setStatus('running')
    setFindings([])
    try {
      const { ok, data: d } = await postScan({ engine: engine.id, client_id: Number(clientId), target })
      if (!ok) { setStatus('error'); showToast('error', d.detail || t('pages.networkIntelligence.scan_failed')); return }
      const jobId = d.job_id ?? ''
      showToast('info', t('pages.networkIntelligence.queued', { label: engine.label, jobId }))
      if (jobId) setPendingJobId(jobId); else setStatus('error')
    } catch (e) {
      setStatus('error')
      showToast('error', e?.message ?? t('pages.networkIntelligence.scan_failed'))
    }
  }, [clientId, engine, target, postScan, showToast, t])

  return (
    <motion.div layout initial={{ opacity: 0, y: 8 }} animate={{ opacity: 1, y: 0 }}
      onMouseEnter={onFocus}
      onFocus={onFocus}
      className="rounded-2xl bg-[var(--bg-2)] backdrop-blur-md border border-[var(--border-default)] p-5 space-y-4 hover:border-[var(--border-strong)] transition-all">
      <div className="flex items-start justify-between gap-3">
        <div className="min-w-0">
          <div className="flex items-center gap-2 mb-1">
            <h3 className="text-sm font-semibold text-white">{engine.label}</h3>
            <StatusBadge status={status} t={t} />
          </div>
          <span className="text-[9px] font-mono text-[var(--text-disabled)] bg-[var(--row-hover-bg)] px-1.5 py-0.5 rounded border border-[var(--border-default)]">{engine.mitre}</span>
        </div>
        <button type="button" onClick={handleRun} disabled={status === 'running' || !clientId}
          className="shrink-0 px-3 py-1.5 rounded-lg text-[11px] font-mono uppercase border border-[#f97316]/30 text-[#f97316]/70 hover:bg-[#f97316]/10 disabled:opacity-40 disabled:cursor-not-allowed transition-all">
          {status === 'running' ? '⟳' : t('pages.networkIntelligence.scan')}
        </button>
      </div>
      <p className="text-[11px] text-[var(--text-muted)] leading-relaxed">{engine.description}</p>
      {engine.commandCenter && (
        <Link to={engine.commandCenter} className="inline-block text-[10px] font-mono text-blue-300/80 hover:text-blue-200">
          → Command Center
        </Link>
      )}
      {lastRun && <p className="text-[10px] font-mono text-[var(--text-disabled)]">{t('pages.networkIntelligence.last_scan', { time: lastRun })}</p>}
      {findings.length > 0 && (
        <div className="space-y-2 pt-2 border-t border-[var(--border-subtle)]">
          <p className="text-[10px] font-mono text-[var(--text-muted)]">{findings.length} findings</p>
          {findings.slice(0, 3).map((f, i) => (
            <div key={i} className="text-[11px] font-mono text-[var(--text-tertiary)] bg-[var(--row-hover-bg)] rounded px-2 py-1 truncate">{f.title ?? f.type}</div>
          ))}
        </div>
      )}
    </motion.div>
  )
}

export default function NetworkIntelligence() {
  const { t } = useTranslation()
  const tt = useCallback((key, def) => t(`pages.networkIntelligence.${key}`, { defaultValue: def }), [t])
  const [clients, setClients] = useState([])
  const [selectedClientId, setSelectedClientId] = useState(null)
  const [focusedEngineId, setFocusedEngineId] = useState(FLAGSHIP_ID)
  const [target, setTarget] = useState('')
  const [targetTouched, setTargetTouched] = useState(false)
  const [toast, setToast] = useState(null)
  const [shellHandlers, setShellHandlers] = useState(null)

  useEffect(() => {
    apiFetch('/api/clients')
      .then((r) => (r.ok ? r.json() : []))
      .then((d) => { if (Array.isArray(d)) setClients(d) })
      .catch(() => {})
  }, [])

  useClientTargetPrefill(selectedClientId, clients, setTarget, { respectTouched: true, targetTouched })

  const showToast = useCallback((sev, msg) => {
    const id = Date.now()
    setToast({ id, sev, msg })
    setTimeout(() => setToast((cur) => (cur?.id === id ? null : cur)), 5000)
  }, [])

  return (
    <PageShell
      engineId={focusedEngineId}
      hideHubParams
      title={t('pages.networkIntelligence.title')}
      badge={t('pages.networkIntelligence.badge')}
      badgeColor="#f97316"
      subtitle={t('pages.networkIntelligence.subtitle', { count: OTHER_ENGINES.length + 1 })}
      actions={shellHandlers ? (
        <ShellScanActions
          onRefresh={shellHandlers.onRefresh}
          onExport={shellHandlers.onExport}
          refreshLoading={shellHandlers.refreshLoading}
          refreshDisabled={shellHandlers.refreshDisabled}
          exportDisabled={shellHandlers.exportDisabled}
        />
      ) : null}
    >
      <div className="flex items-end gap-3 mb-6 flex-wrap">
        <label className="space-y-1">
          <span className="block text-[10px] font-mono text-[var(--text-muted)] uppercase tracking-wider">{t('pages.networkIntelligence.client_label')}</span>
          <select value={selectedClientId ?? ''} onChange={(e) => { setSelectedClientId(e.target.value || null); setTargetTouched(false) }}
            className="bg-[var(--scrim)] border border-[var(--border-default)] rounded-lg px-3 py-1.5 text-xs text-[var(--text-secondary)] font-mono focus:outline-none focus:border-[#f97316]/40 min-w-[180px]">
            <option value="">{t('pages.networkIntelligence.select_client')}</option>
            {clients.map((c) => <option key={c.id} value={c.id}>{c.name}</option>)}
          </select>
        </label>
        <label className="space-y-1">
          <span className="block text-[10px] font-mono text-[var(--text-muted)] uppercase tracking-wider">{tt('target_label', 'Target host / domain')}</span>
          <input type="text" value={target} placeholder={tt('target_placeholder', 'example.com')}
            onChange={(e) => { setTarget(e.target.value); setTargetTouched(true) }}
            className="bg-[var(--scrim)] border border-[var(--border-default)] rounded-lg px-3 py-1.5 text-xs text-[var(--text-secondary)] font-mono focus:outline-none focus:border-[#f97316]/40 min-w-[260px]" />
        </label>
      </div>

      {toast && (
        <div className={`fixed top-16 right-4 z-50 rounded-xl border px-4 py-3 text-sm font-mono max-w-sm shadow-2xl ${toast.sev === 'error' ? 'bg-rose-950/90 border-rose-500/40 text-rose-200' : 'bg-[var(--bg-1)] border-[#f97316]/30 text-[#f97316]'}`}>
          {toast.msg}
        </div>
      )}

      {!selectedClientId && (
        <div className="rounded-xl border border-amber-500/20 bg-amber-950/20 px-4 py-3 text-sm text-amber-200/80 font-mono mb-6">
          {t('pages.networkIntelligence.select_client_warning')}
        </div>
      )}

      <BgpDnsFlagship
        clientId={selectedClientId}
        target={target}
        showToast={showToast}
        t={t}
        tt={tt}
        isFocused={focusedEngineId === FLAGSHIP_ID}
        onFocus={() => setFocusedEngineId(FLAGSHIP_ID)}
        onShellReady={setShellHandlers}
      />

      <h3 className="text-[11px] font-mono text-[var(--text-muted)] uppercase tracking-widest mt-8 mb-4">{tt('other_engines', 'Other Network Engines')}</h3>
      <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
        {OTHER_ENGINES.map((engine) => (
          <NetworkEngineCard
            key={engine.id}
            engine={engine}
            clientId={selectedClientId}
            target={target}
            isFocused={focusedEngineId === engine.id}
            onFocus={() => setFocusedEngineId(engine.id)}
            showToast={showToast}
            t={t}
          />
        ))}
      </div>
    </PageShell>
  )
}
