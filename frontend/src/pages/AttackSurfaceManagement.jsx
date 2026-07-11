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
import Button from '../components/ui/Button'

const ENGINE = 'asm'
const ACCENT = '#22d3ee'

// ─── Constants ────────────────────────────────────────────────────────────────

const SEVERITY_META = {
  critical: { color: '#ef4444', labelKey: 'pages.attackSurfaceManagement.severity_critical' },
  high: { color: '#f97316', labelKey: 'pages.attackSurfaceManagement.severity_high' },
  medium: { color: '#f59e0b', labelKey: 'pages.attackSurfaceManagement.severity_medium' },
  low: { color: '#22d3ee', labelKey: 'pages.attackSurfaceManagement.severity_low' },
  info: { color: '#6b7280', labelKey: 'pages.attackSurfaceManagement.severity_info' },
}

const ASSET_META = {
  inventory: { icon: '🗂', labelKey: 'pages.attackSurfaceManagement.asset_inventory' },
  dns: { icon: '🧭', labelKey: 'pages.attackSurfaceManagement.asset_dns' },
  email_posture: { icon: '✉️', labelKey: 'pages.attackSurfaceManagement.asset_email_posture' },
  port: { icon: '🔌', labelKey: 'pages.attackSurfaceManagement.asset_port' },
  banner: { icon: '📡', labelKey: 'pages.attackSurfaceManagement.asset_banner' },
  http_posture: { icon: '🌐', labelKey: 'pages.attackSurfaceManagement.asset_http_posture' },
  tls_posture: { icon: '🔒', labelKey: 'pages.attackSurfaceManagement.asset_tls_posture' },
  cloud_footprint: { icon: '☁️', labelKey: 'pages.attackSurfaceManagement.asset_cloud_footprint' },
  fingerprint: { icon: '🧬', labelKey: 'pages.attackSurfaceManagement.asset_fingerprint' },
  cloud_hunter: { icon: '🎯', labelKey: 'pages.attackSurfaceManagement.asset_cloud_hunter' },
  shadow_it: { icon: '👻', labelKey: 'pages.attackSurfaceManagement.asset_shadow_it' },
  attack_path: { icon: '⛓', labelKey: 'pages.attackSurfaceManagement.asset_attack_path' },
  wellknown: { icon: '📋', labelKey: 'pages.attackSurfaceManagement.asset_wellknown' },
  rdap: { icon: '🏛', labelKey: 'pages.attackSurfaceManagement.asset_rdap' },
  asn: { icon: '🛰', labelKey: 'pages.attackSurfaceManagement.asset_asn' },
  cors: { icon: '🔀', labelKey: 'pages.attackSurfaceManagement.asset_cors' },
  sensitive_path: { icon: '🚨', labelKey: 'pages.attackSurfaceManagement.asset_sensitive_path' },
  robots: { icon: '🤖', labelKey: 'pages.attackSurfaceManagement.asset_robots' },
  report: { icon: '📊', labelKey: 'pages.attackSurfaceManagement.asset_report' },
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
  { key: 'port_scan', labelKey: 'pages.attackSurfaceManagement.toggle_port_scan_label', hintKey: 'pages.attackSurfaceManagement.toggle_port_scan_hint' },
  { key: 'banner_grab', labelKey: 'pages.attackSurfaceManagement.toggle_banner_grab_label', hintKey: 'pages.attackSurfaceManagement.toggle_banner_grab_hint' },
  { key: 'subdomain_enum', labelKey: 'pages.attackSurfaceManagement.toggle_subdomain_enum_label', hintKey: 'pages.attackSurfaceManagement.toggle_subdomain_enum_hint' },
  { key: 'dns_intel', labelKey: 'pages.attackSurfaceManagement.toggle_dns_intel_label', hintKey: 'pages.attackSurfaceManagement.toggle_dns_intel_hint' },
  { key: 'dkim_probe', labelKey: 'pages.attackSurfaceManagement.toggle_dkim_probe_label', hintKey: 'pages.attackSurfaceManagement.toggle_dkim_probe_hint' },
  { key: 'dns_hardening', labelKey: 'pages.attackSurfaceManagement.toggle_dns_hardening_label', hintKey: 'pages.attackSurfaceManagement.toggle_dns_hardening_hint' },
  { key: 'rdap_intel', labelKey: 'pages.attackSurfaceManagement.toggle_rdap_intel_label', hintKey: 'pages.attackSurfaceManagement.toggle_rdap_intel_hint' },
  { key: 'ip_asn_enrichment', labelKey: 'pages.attackSurfaceManagement.toggle_ip_asn_enrichment_label', hintKey: 'pages.attackSurfaceManagement.toggle_ip_asn_enrichment_hint' },
  { key: 'http_posture', labelKey: 'pages.attackSurfaceManagement.toggle_http_posture_label', hintKey: 'pages.attackSurfaceManagement.toggle_http_posture_hint' },
  { key: 'cors_probe', labelKey: 'pages.attackSurfaceManagement.toggle_cors_probe_label', hintKey: 'pages.attackSurfaceManagement.toggle_cors_probe_hint' },
  { key: 'sensitive_path_probe', labelKey: 'pages.attackSurfaceManagement.toggle_sensitive_path_probe_label', hintKey: 'pages.attackSurfaceManagement.toggle_sensitive_path_probe_hint' },
  { key: 'robots_harvest', labelKey: 'pages.attackSurfaceManagement.toggle_robots_harvest_label', hintKey: 'pages.attackSurfaceManagement.toggle_robots_harvest_hint' },
  { key: 'cleartext_http_probe', labelKey: 'pages.attackSurfaceManagement.toggle_cleartext_http_probe_label', hintKey: 'pages.attackSurfaceManagement.toggle_cleartext_http_probe_hint' },
  { key: 'wellknown_probe', labelKey: 'pages.attackSurfaceManagement.toggle_wellknown_probe_label', hintKey: 'pages.attackSurfaceManagement.toggle_wellknown_probe_hint' },
  { key: 'tls_posture', labelKey: 'pages.attackSurfaceManagement.toggle_tls_posture_label', hintKey: 'pages.attackSurfaceManagement.toggle_tls_posture_hint' },
  { key: 'cloud_hunter', labelKey: 'pages.attackSurfaceManagement.toggle_cloud_hunter_label', hintKey: 'pages.attackSurfaceManagement.toggle_cloud_hunter_hint' },
  { key: 'shadow_it_scan', labelKey: 'pages.attackSurfaceManagement.toggle_shadow_it_scan_label', hintKey: 'pages.attackSurfaceManagement.toggle_shadow_it_scan_hint' },
  { key: 'tech_fingerprint', labelKey: 'pages.attackSurfaceManagement.toggle_tech_fingerprint_label', hintKey: 'pages.attackSurfaceManagement.toggle_tech_fingerprint_hint' },
  { key: 'attack_path_correlation', labelKey: 'pages.attackSurfaceManagement.toggle_attack_path_correlation_label', hintKey: 'pages.attackSurfaceManagement.toggle_attack_path_correlation_hint' },
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
    <Button variant="unstyled"
      type="button"
      role="switch"
      aria-checked={checked}
      disabled={disabled}
      onClick={() => onChange(!checked)}
      className={`relative shrink-0 w-10 h-5 rounded-full transition-all duration-300 disabled:opacity-40 ${
        checked ? 'bg-cyan-500/40 shadow-[inset_0_0_8px_rgba(34,211,238,0.3)]' : 'bg-[var(--scrim)] border border-[var(--border-default)]'
      }`}
    >
      <span className={`absolute top-0.5 w-4 h-4 rounded-full bg-white shadow transition-all duration-300 ${checked ? 'left-[22px]' : 'left-0.5'}`} />
    </Button>
  )
}

function MetricCard({ label, value, sub, accent = '#22d3ee', icon }) {
  return (
    <div className="relative overflow-hidden rounded-2xl border border-white/[0.08] bg-gradient-to-br from-white/[0.06] to-black/50 p-4">
      <div className="absolute top-0 inset-x-0 h-px opacity-60" style={{ background: `linear-gradient(90deg, transparent, ${accent}60, transparent)` }} />
      <div className="flex items-start justify-between gap-2">
        <div className="min-w-0">
          <p className="text-[10px] font-mono uppercase tracking-[0.18em] text-[var(--text-muted)] mb-1.5">{label}</p>
          <p className="text-2xl font-bold text-white tracking-tight truncate">{value}</p>
          {sub && <p className="text-[10px] font-mono text-[var(--text-muted)] mt-1 truncate">{sub}</p>}
        </div>
        {icon && <span className="text-lg opacity-70 shrink-0">{icon}</span>}
      </div>
    </div>
  )
}

function ScoreRing({ score, grade }) {
  const { t } = useTranslation()
  const color = gradeColor(grade)
  const deg = Math.round((Math.max(0, Math.min(100, score)) / 100) * 360)
  return (
    <div className="relative w-36 h-36 shrink-0" title={t('pages.attackSurfaceManagement.score_ring_tooltip', { score })}>
      <div
        className="absolute inset-0 rounded-full"
        style={{ background: `conic-gradient(${color} ${deg}deg, rgba(255,255,255,0.06) ${deg}deg)` }}
      />
      <div className="absolute inset-[10px] rounded-full bg-[#0a0f1c] border border-[var(--border-default)] flex flex-col items-center justify-center">
        <span className="text-4xl font-black" style={{ color }}>{grade}</span>
        <span className="text-[11px] font-mono text-[var(--text-tertiary)]">{score}/100</span>
      </div>
    </div>
  )
}

function SeverityBar({ counts }) {
  const { t } = useTranslation()
  const order = ['critical', 'high', 'medium', 'low', 'info']
  const total = order.reduce((a, k) => a + (counts?.[k] ?? 0), 0) || 1
  return (
    <div className="space-y-2 w-full">
      <div className="flex h-2.5 w-full overflow-hidden rounded-full bg-[var(--bg-3)]">
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
            {counts?.[k] ?? 0} {t(SEVERITY_META[k].labelKey)}
          </span>
        ))}
      </div>
    </div>
  )
}

function AttackPathPanel({ paths }) {
  const { t } = useTranslation()
  if (!paths?.length) return null
  return (
    <div className="rounded-2xl border border-rose-500/25 bg-gradient-to-br from-rose-950/20 to-black/50 p-5">
      <p className="text-[10px] font-mono uppercase tracking-widest text-rose-300/70 mb-3">⛓ {t('pages.attackSurfaceManagement.header_correlated_attack_paths')}</p>
      <div className="space-y-2">
        {paths.map((p, i) => {
          const sev = (p.severity || 'critical').toLowerCase()
          return (
            <div key={i} className="rounded-xl border border-rose-500/20 bg-[var(--bg-2)] px-4 py-3">
              <div className="flex items-start justify-between gap-3">
                <p className="text-sm font-semibold text-[var(--text-primary)]">{p.title}</p>
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
  const { t } = useTranslation()
  if (!queue?.length) return null
  return (
    <div className="rounded-2xl border border-emerald-500/20 bg-[var(--bg-2)] p-5">
      <p className="text-[10px] font-mono uppercase tracking-widest text-emerald-300/70 mb-3">→ {t('pages.attackSurfaceManagement.header_remediation_queue')}</p>
      <ol className="space-y-2">
        {queue.map((item, i) => (
          <li key={i} className="flex gap-3 text-[12px] font-mono">
            <span className="text-emerald-400/80 shrink-0 w-5">{i + 1}.</span>
            <div className="min-w-0">
              <p className="text-[var(--text-primary)]">{item.title}</p>
              {item.remediation && <p className="text-[var(--text-muted)] text-[11px] mt-0.5">{item.remediation}</p>}
            </div>
            <span className="text-[9px] uppercase shrink-0 ml-auto" style={{ color: severityColor(item.severity) }}>{item.severity}</span>
          </li>
        ))}
      </ol>
    </div>
  )
}

function SubdomainInventory({ hosts }) {
  const { t } = useTranslation()
  if (!hosts?.length) return null
  return (
    <div className="rounded-2xl border border-white/[0.08] bg-[var(--bg-2)] p-5">
      <p className="text-[10px] font-mono uppercase tracking-widest text-[var(--text-muted)] mb-3">🗂 {t('pages.attackSurfaceManagement.header_subdomain_inventory')} ({hosts.length})</p>
      <div className="flex flex-wrap gap-1.5 max-h-40 overflow-y-auto">
        {hosts.map((h) => (
          <span key={h} className="text-[10px] font-mono px-2 py-1 rounded-lg bg-cyan-500/[0.06] border border-cyan-500/15 text-cyan-200/80">{h}</span>
        ))}
      </div>
    </div>
  )
}

function FindingCard({ f }) {
  const { t } = useTranslation()
  const sev = (f.severity || 'info').toLowerCase()
  const assetMeta = ASSET_META[f.asset]
  const assetIcon = assetMeta?.icon ?? '◆'
  const assetLabel = assetMeta ? t(assetMeta.labelKey) : (f.asset || t('pages.attackSurfaceManagement.finding_default_label'))
  return (
    <div className="rounded-xl bg-[var(--bg-2)] border border-[var(--border-default)] p-3.5 space-y-2 hover:border-[var(--border-strong)] transition-colors">
      <div className="flex items-start justify-between gap-3">
        <div className="flex items-start gap-2 min-w-0">
          <span className="text-base shrink-0 mt-0.5">{assetIcon}</span>
          <div className="min-w-0">
            <p className="text-sm font-semibold text-[var(--text-primary)] leading-snug">{f.title || f.value}</p>
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
      {f.description && <p className="text-[11px] text-[var(--text-tertiary)] font-mono leading-relaxed">{f.description}</p>}
      {f.remediation && (
        <p className="text-[11px] text-emerald-300/70 font-mono leading-relaxed">
          <span className="text-emerald-400/90">→ {t('pages.attackSurfaceManagement.finding_fix_label')}: </span>{f.remediation}
        </p>
      )}
      <div className="flex flex-wrap items-center gap-2 pt-0.5">
        <span className="text-[9px] font-mono px-1.5 py-0.5 rounded bg-[var(--row-hover-bg)] text-[var(--text-muted)] border border-white/[0.06]">{assetLabel}</span>
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
  const { t } = useTranslation()
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
    if (!selectedClientId) { showToast('error', t('pages.attackSurfaceManagement.toast_select_client')); return }
    if (!target.trim()) { showToast('error', t('pages.attackSurfaceManagement.toast_enter_target')); return }
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
        showToast('error', d.detail || d.error || t('pages.attackSurfaceManagement.toast_scan_failed', { status }))
        return
      }
      const jid = d.job_id ?? ''
      showToast('info', t('pages.attackSurfaceManagement.toast_scan_queued', { jid }))
      if (jid) { setJobId(jid); setShowConfig(false) } else setStatus('error')
    } catch (e) {
      setStatus('error')
      showToast('error', e?.message ?? t('pages.attackSurfaceManagement.toast_network_error'))
    }
  }, [selectedClientId, target, params, showToast, t])

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
    showToast('info', t('pages.attackSurfaceManagement.toast_exported'))
  }, [report, issues, target, showToast, t])

  const statusBadge = {
    idle: { c: '#6b7280', t: t('pages.attackSurfaceManagement.status_idle') },
    running: { c: '#22d3ee', t: t('pages.attackSurfaceManagement.status_scanning') },
    completed: { c: '#22c55e', t: t('pages.attackSurfaceManagement.status_completed') },
    error: { c: '#ef4444', t: t('pages.attackSurfaceManagement.status_error') },
  }[status]

  return (
    <PageShell
      hideHubParams
      title={t('pages.attackSurfaceManagement.page_title')}
      badge="EASM"
      badgeColor={ACCENT}
      subtitle={t('pages.attackSurfaceManagement.page_subtitle')}
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
              toast.sev === 'error' ? 'bg-rose-950/90 border-rose-500/40 text-rose-200' : 'bg-[var(--bg-1)] border-cyan-500/30 text-cyan-200'
            }`}
          >
            {toast.msg}
          </motion.div>
        )}
      </AnimatePresence>

      {/* ── Control bar ─────────────────────────────────────────────── */}
      <div className="rounded-2xl border border-white/[0.08] bg-[var(--bg-2)] p-4 mb-5">
        <div className="flex flex-wrap items-end gap-3">
          <div className="flex flex-col gap-1">
            <label className="text-[10px] font-mono uppercase tracking-wider text-[var(--text-muted)]">{t('pages.attackSurfaceManagement.label_client')}</label>
            <select
              value={selectedClientId ?? ''}
              onChange={(e) => setSelectedClientId(e.target.value || null)}
              className="bg-[var(--scrim)] border border-[var(--border-default)] rounded-lg px-3 py-2 text-sm text-[var(--text-primary)] font-mono focus:outline-none focus:border-cyan-500/40 min-w-[180px]"
            >
              <option value="">{t('pages.attackSurfaceManagement.select_client_placeholder')}</option>
              {clients.map((c) => <option key={c.id} value={c.id}>{c.name}</option>)}
            </select>
          </div>
          <div className="flex flex-col gap-1 flex-1 min-w-[220px]">
            <label className="text-[10px] font-mono uppercase tracking-wider text-[var(--text-muted)]">{t('pages.attackSurfaceManagement.label_target')}</label>
            <input
              type="text" value={target} onChange={(e) => setTarget(e.target.value)}
              placeholder="example.com"
              className="bg-[var(--scrim)] border border-[var(--border-default)] rounded-lg px-3 py-2 text-sm text-[var(--text-primary)] font-mono placeholder-white/25 focus:outline-none focus:border-cyan-500/40"
            />
          </div>
          <Button variant="unstyled"
            type="button"
            onClick={() => setShowConfig((s) => !s)}
            className="px-3 py-2 rounded-lg text-xs font-mono border border-[var(--border-default)] text-[var(--text-tertiary)] hover:text-[var(--text-primary)] hover:border-[var(--border-strong)] transition-all"
          >
            {showConfig ? `▾ ${t('pages.attackSurfaceManagement.btn_hide_config')}` : `▸ ${t('pages.attackSurfaceManagement.btn_scan_config')}`}
          </Button>
          <Button variant="unstyled"
            type="button"
            onClick={handleRun}
            disabled={status === 'running' || !selectedClientId}
            className="px-5 py-2 rounded-lg text-sm font-mono font-semibold bg-cyan-500/20 border border-cyan-500/40 text-cyan-200 hover:bg-cyan-500/30 disabled:opacity-40 disabled:cursor-not-allowed transition-all"
          >
            {status === 'running' ? `⟳ ${t('pages.attackSurfaceManagement.btn_scanning')}` : `▶ ${t('pages.attackSurfaceManagement.btn_map_attack_surface')}`}
          </Button>
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
                  <p className="text-[10px] font-mono uppercase tracking-widest text-[var(--text-muted)]">{t('pages.attackSurfaceManagement.header_modules')}</p>
                  {TOGGLES.map((tg) => (
                    <div key={tg.key} className="flex items-center justify-between gap-3">
                      <div className="min-w-0">
                        <p className="text-[12px] text-[var(--text-secondary)]">{t(tg.labelKey)}</p>
                        <p className="text-[10px] font-mono text-[var(--text-muted)]">{t(tg.hintKey)}</p>
                      </div>
                      <Toggle checked={!!params[tg.key]} onChange={(v) => setParam(tg.key, v)} disabled={status === 'running'} />
                    </div>
                  ))}
                </div>
                <div className="space-y-3">
                  <p className="text-[10px] font-mono uppercase tracking-widest text-[var(--text-muted)]">{t('pages.attackSurfaceManagement.header_parameters')}</p>
                  <div className="grid grid-cols-2 gap-3">
                    <Field label={t('pages.attackSurfaceManagement.field_ports')}>
                      <input className={inputCls} value={params.ports} onChange={(e) => setParam('ports', e.target.value)}
                        placeholder="top | all | 80,443,8080-8090" />
                    </Field>
                    <Field label={t('pages.attackSurfaceManagement.field_subdomain_sources')}>
                      <select className={inputCls} value={params.subdomain_sources} onChange={(e) => setParam('subdomain_sources', e.target.value)}>
                        <option value="both">{t('pages.attackSurfaceManagement.opt_passive_brute')}</option>
                        <option value="passive">{t('pages.attackSurfaceManagement.opt_passive_ct')}</option>
                        <option value="bruteforce">{t('pages.attackSurfaceManagement.opt_bruteforce')}</option>
                      </select>
                    </Field>
                    <Field label={t('pages.attackSurfaceManagement.field_max_subdomains')}>
                      <input type="number" className={inputCls} value={params.max_subdomains} min={0} max={500}
                        onChange={(e) => setParam('max_subdomains', Number(e.target.value))} />
                    </Field>
                    <Field label={t('pages.attackSurfaceManagement.field_severity_threshold')}>
                      <select className={inputCls} value={params.severity_threshold} onChange={(e) => setParam('severity_threshold', e.target.value)}>
                        {['info', 'low', 'medium', 'high', 'critical'].map((s) => <option key={s} value={s}>{s}</option>)}
                      </select>
                    </Field>
                    <Field label={t('pages.attackSurfaceManagement.field_port_timeout')}>
                      <input type="number" className={inputCls} value={params.port_timeout_ms} min={100} max={5000}
                        onChange={(e) => setParam('port_timeout_ms', Number(e.target.value))} />
                    </Field>
                    <Field label={t('pages.attackSurfaceManagement.field_http_timeout')}>
                      <input type="number" className={inputCls} value={params.http_timeout_ms} min={1000} max={30000}
                        onChange={(e) => setParam('http_timeout_ms', Number(e.target.value))} />
                    </Field>
                    <Field label={t('pages.attackSurfaceManagement.field_max_findings')}>
                      <input type="number" className={inputCls} value={params.max_findings} min={1} max={5000}
                        onChange={(e) => setParam('max_findings', Number(e.target.value))} />
                    </Field>
                  </div>
                  <Field label={t('pages.attackSurfaceManagement.field_wordlist')}>
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
            <p className="text-sm font-mono text-[var(--text-tertiary)]">{t('pages.attackSurfaceManagement.empty_running')}</p>
          </div>
        </div>
      )}

      {report && (
        <motion.div initial={{ opacity: 0, y: 12 }} animate={{ opacity: 1, y: 0 }} className="space-y-5">
          <div className="flex justify-end">
            <Button variant="unstyled"
              type="button"
              onClick={handleExport}
              className="px-3 py-1.5 rounded-lg text-[11px] font-mono border border-[var(--border-strong)] text-[var(--text-tertiary)] hover:text-[var(--text-primary)] hover:border-[var(--border-strong)] transition-all"
            >
              ↓ {t('pages.attackSurfaceManagement.btn_export_json')}
            </Button>
          </div>
          {/* Hero */}
          <div className="rounded-2xl border border-white/[0.08] bg-gradient-to-br from-white/[0.06] via-black/40 to-black/60 p-6">
            <div className="flex flex-col md:flex-row items-center gap-6">
              <ScoreRing score={score ?? 0} grade={grade} />
              <div className="flex-1 w-full space-y-3">
                <div>
                  <h2 className="text-lg font-bold text-white">{t('pages.attackSurfaceManagement.hero_score_title')} — {report.host}</h2>
                  <p className="text-[12px] text-[var(--text-tertiary)] font-mono">{report.description}</p>
                </div>
                <SeverityBar counts={severityCounts} />
              </div>
            </div>
          </div>

          {/* Metrics */}
          <div className="grid grid-cols-2 lg:grid-cols-4 xl:grid-cols-6 gap-4">
            <MetricCard label={t('pages.attackSurfaceManagement.metric_subdomain_assets')} value={report.subdomain_count ?? 0} accent="#22d3ee" icon="🗂" />
            <MetricCard label={t('pages.attackSurfaceManagement.metric_exposed_services')} value={report.exposed_services ?? 0} accent="#f97316" icon="🔌" />
            <MetricCard label={t('pages.attackSurfaceManagement.metric_takeover_risks')} value={report.takeover_risks ?? 0} accent="#ef4444" icon="🎯" />
            <MetricCard label={t('pages.attackSurfaceManagement.metric_attack_paths')} value={report.attack_paths ?? 0} accent="#f43f5e" icon="⛓" />
            <MetricCard label={t('pages.attackSurfaceManagement.metric_shadow_it')} value={report.shadow_it_signals ?? 0} accent="#a78bfa" icon="👻" />
            <MetricCard label={t('pages.attackSurfaceManagement.metric_service_banners')} value={report.service_banners ?? 0} accent="#84cc16" icon="📡" />
          </div>

          <AttackPathPanel paths={attackPaths} />
          <RemediationPanel queue={remediationQueue} />
          <SubdomainInventory hosts={subdomainInventory} />

          {/* Exposure by asset */}
          {Object.keys(exposureByAsset).length > 0 && (
            <div className="rounded-2xl border border-white/[0.08] bg-[var(--bg-2)] p-5">
              <p className="text-[10px] font-mono uppercase tracking-widest text-[var(--text-muted)] mb-3">{t('pages.attackSurfaceManagement.header_exposure_by_category')}</p>
              <div className="space-y-2">
                {Object.entries(exposureByAsset).sort((a, b) => b[1] - a[1]).map(([asset, n]) => {
                  const max = Math.max(...Object.values(exposureByAsset))
                  const meta = ASSET_META[asset]
                  const metaIcon = meta?.icon ?? '◆'
                  const metaLabel = meta ? t(meta.labelKey) : asset
                  return (
                    <div key={asset} className="flex items-center gap-3">
                      <span className="text-[11px] font-mono text-[var(--text-tertiary)] w-44 shrink-0 truncate">{metaIcon} {metaLabel}</span>
                      <div className="flex-1 h-2 rounded-full bg-[var(--bg-3)] overflow-hidden">
                        <div className="h-full rounded-full bg-cyan-500/60" style={{ width: `${(n / max) * 100}%` }} />
                      </div>
                      <span className="text-[11px] font-mono text-[var(--text-tertiary)] w-8 text-right">{n}</span>
                    </div>
                  )
                })}
              </div>
            </div>
          )}

          {assetTypes.length > 2 && (
            <div className="flex flex-wrap gap-1.5">
              {assetTypes.map((a) => (
                <Button variant="unstyled" key={a} type="button" onClick={() => setAssetFilter(a)}
                  className={`px-2.5 py-1 rounded-lg text-[10px] font-mono border transition-all ${
                    assetFilter === a ? 'text-cyan-200 border-cyan-500/40 bg-cyan-500/10' : 'text-[var(--text-muted)] border-white/[0.08] hover:text-[var(--text-secondary)]'
                  }`}
                >
                  {a === 'all' ? t('pages.attackSurfaceManagement.filter_all_categories') : `${ASSET_META[a]?.icon ?? '◆'} ${ASSET_META[a] ? t(ASSET_META[a].labelKey) : a}`}
                </Button>
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
            emptyReadyTitle={t('pages.attackSurfaceManagement.empty_ready_title')}
            emptyReadyBody={t('pages.attackSurfaceManagement.empty_ready_body')}
            renderFinding={(f, i) => <FindingCard key={i} f={f} />}
          />
        </motion.div>
      )}

      {!report && status !== 'running' && (
        <div className="rounded-2xl border border-white/[0.08] bg-[var(--table-surface)] px-6 py-16 text-center">
          <p className="text-4xl mb-3">🛰️</p>
          <p className="text-sm font-mono text-[var(--text-tertiary)]">{t('pages.attackSurfaceManagement.empty_ready_title')}</p>
          <p className="text-[11px] font-mono text-[var(--text-disabled)] mt-1">{t('pages.attackSurfaceManagement.empty_bottom_body')}</p>
        </div>
      )}
    </PageShell>
  )
}

const inputCls = 'w-full bg-[var(--scrim)] border border-[var(--border-default)] rounded-lg px-2.5 py-1.5 text-[12px] text-[var(--text-primary)] font-mono placeholder-white/25 focus:outline-none focus:border-cyan-500/40'

function Field({ label, children }) {
  return (
    <div className="flex flex-col gap-1">
      <label className="text-[10px] font-mono uppercase tracking-wider text-[var(--text-muted)]">{label}</label>
      {children}
    </div>
  )
}
