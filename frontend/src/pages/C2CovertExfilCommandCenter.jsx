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
import { useJobPoll, resolveJobFindings, uiJobStatus } from '../lib/useJobPoll'
import Button from '../components/ui/Button'

const ENGINE = 'advanced_c2_covert_exfil'
const ACCENT = '#22d3ee'

const PROBE_TOGGLES = [
  { key: 'check_beaconing', label: 'Beacon jitter / health masquerade', hint: 'Multi-sample RTT, Z-score, padding', defaultVal: true },
  { key: 'check_dns_tunnel', label: 'DNS TXT entropy / TTL / DoH', hint: 'Live TXT + DoH path probes', defaultVal: true },
  { key: 'check_http3_ws', label: 'HTTP/3 Alt-Svc + WebSocket', hint: 'QUIC advertisement and WSS upgrade', defaultVal: true },
  { key: 'check_icmp_ntp', label: 'ICMP echo + NTP UDP/123', hint: 'Covert-channel feasibility, not an implant', defaultVal: true },
  { key: 'check_steganography', label: 'Public-image LSB / EXIF', hint: 'Entropy + chi-square on origin media', defaultVal: true },
  { key: 'check_proxy_tor', label: 'CDN / Tor / domain-fronting', hint: 'Cloudflare, Fastly, onion references', defaultVal: true },
  { key: 'check_ports', label: 'Ingress C2 fallback ports', hint: '53, 123, 4443, 9001, 8080…', defaultVal: true },
  { key: 'attack_path_synthesis', label: 'Choke-point / Dijkstra paths', hint: 'Internet → unusual port → origin', defaultVal: true },
  { key: 'posture_scoring', label: 'Posture score', hint: '0–100 covert-channel grade', defaultVal: true },
  { key: 'fair_sle', label: 'FAIR SLE pricing', hint: 'asset_value × max(CVSS/10, 0.5)', defaultVal: true },
  { key: 'emit_coverage_manifest', label: 'Coverage manifest', hint: 'Audit trail of every live layer', defaultVal: true },
  { key: 'include_agent_findings', label: 'Honest agent-required notes', hint: 'ICMP payload entropy needs NDR/agent', defaultVal: true },
]

const CATEGORY_META = {
  posture_score: { label: 'Posture', icon: '◈', color: ACCENT, order: 0 },
  beacon_jitter: { label: 'Beacon jitter', icon: '⏱', color: '#f472b6', order: 1 },
  beacon_padding: { label: 'Beacon padding', icon: '▣', color: '#fb7185', order: 2 },
  beacon_zscore: { label: 'Z-score adapt', icon: 'σ', color: '#a78bfa', order: 3 },
  c2_masquerade: { label: 'C2 masquerade', icon: '🎭', color: '#818cf8', order: 4 },
  c2_hmac: { label: 'HMAC headers', icon: '🔏', color: '#ef4444', order: 5 },
  c2_ua_split: { label: 'UA split', icon: 'U', color: '#fb7185', order: 5.5 },
  c2_path_surface: { label: 'C2 paths', icon: '/', color: '#f97316', order: 6 },
  dns_entropy: { label: 'DNS entropy', icon: '〰', color: '#eab308', order: 7 },
  dns_txt_length: { label: 'DNS TXT', icon: 'T', color: '#fbbf24', order: 8 },
  dns_ttl: { label: 'DNS TTL', icon: '0', color: '#facc15', order: 9 },
  doh_endpoint: { label: 'DoH', icon: 'H', color: '#f87171', order: 10 },
  http3_altsvc: { label: 'HTTP/3', icon: '3', color: '#22d3ee', order: 11 },
  websocket_c2: { label: 'WebSocket', icon: '⟁', color: '#38bdf8', order: 12 },
  ntp_udp: { label: 'NTP', icon: '⌚', color: '#34d399', order: 13 },
  icmp_echo: { label: 'ICMP', icon: '◌', color: '#4ade80', order: 14 },
  stego_lsb: { label: 'LSB stego', icon: '🖼', color: '#fb923c', order: 15 },
  stego_png_entropy: { label: 'PNG entropy', icon: 'P', color: '#fdba74', order: 16 },
  cdn_fronting: { label: 'CDN fronting', icon: '☁', color: '#94a3b8', order: 17 },
  tor_reference: { label: 'Tor', icon: '🧅', color: '#a3a3a3', order: 18 },
  ingress_ports: { label: 'Ingress ports', icon: '☰', color: '#f43f5e', order: 19 },
  choke_point: { label: 'Choke-point', icon: '⬡', color: '#e11d48', order: 20 },
  fair_sle: { label: 'FAIR SLE', icon: '$', color: '#fbbf24', order: 21 },
  coverage_manifest: { label: 'Coverage', icon: '✓', color: ACCENT, order: 22 },
  agent_required: { label: 'Agent', icon: '📡', color: '#64748b', order: 23 },
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

function isSummary(f) {
  return f?.category === 'posture_score' || (typeof f?.title === 'string' && f.title.includes('covert-exfil posture'))
}

function extractScore(findings) {
  const s = findings.find(isSummary)
  return s?.evidence?.score ?? s?.score ?? null
}

function extractGrade(findings) {
  const s = findings.find(isSummary)
  return s?.evidence?.grade ?? s?.grade ?? null
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
    <div className="flex flex-wrap gap-2 mb-4">
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

function Scorecard({ score, grade }) {
  if (score == null && !grade) return null
  return (
    <div className="rounded-2xl border border-cyan-500/30 bg-cyan-500/5 p-5 mb-6 flex flex-wrap items-center gap-6">
      <div>
        <div className="text-[10px] font-mono uppercase tracking-widest text-[var(--text-muted)]">Covert-channel posture</div>
        <div className="text-4xl font-mono font-semibold" style={{ color: gradeColor(grade) }}>
          {score ?? '—'}<span className="text-lg text-[var(--text-muted)]">/100</span>
        </div>
      </div>
      <div
        className="w-16 h-16 rounded-2xl flex items-center justify-center text-2xl font-mono font-bold border"
        style={{ color: gradeColor(grade), borderColor: `${gradeColor(grade)}55`, background: `${gradeColor(grade)}18` }}
      >
        {grade || '—'}
      </div>
      <p className="text-xs text-[var(--text-secondary)] max-w-xl font-mono">
        Live fused assessment — beacon Z-score, DNS entropy, HTTP/3/WSS, NTP/ICMP feasibility, LSB stego, CDN/Tor fronting, ingress choke-points. No simulated findings.
      </p>
    </div>
  )
}

function FindingCard({ f }) {
  const sev = (f?.severity || 'info').toLowerCase()
  const st = SEV_STYLE[sev] || SEV_STYLE.info
  const ev = f?.evidence && typeof f.evidence === 'object' ? f.evidence : null
  return (
    <article className={`rounded-xl border p-4 ${st.bd} ${st.bg}`}>
      <div className="flex flex-wrap items-center gap-2 mb-1">
        <span className={`text-[10px] font-mono uppercase ${st.text}`}>{sev}</span>
        {f?.mitre_attack ? <span className="text-[10px] font-mono text-cyan-300/80">{f.mitre_attack}</span> : null}
        {f?.category ? <span className="text-[10px] font-mono text-[var(--text-muted)]">{f.category}</span> : null}
      </div>
      <h3 className="text-sm font-medium text-[var(--text-primary)]">{f?.title}</h3>
      {f?.description ? <p className="mt-1 text-xs text-[var(--text-secondary)] leading-relaxed">{f.description}</p> : null}
      {ev ? (
        <pre className="mt-2 text-[10px] font-mono text-[var(--text-muted)] overflow-x-auto max-h-32">
          {JSON.stringify(ev, null, 0)}
        </pre>
      ) : null}
    </article>
  )
}

export default function C2CovertExfilCommandCenter() {
  const { t } = useTranslation()
  const [clients, setClients] = useState([])
  const [clientId, setClientId] = useState('')
  const { postScan } = useCommandCenterScan(clientId)
  const [target, setTarget] = useState('')
  const [targetTouched, setTargetTouched] = useState(false)
  const [intensity, setIntensity] = useState('normal')
  const [ports, setPorts] = useState('')
  const [assetValue, setAssetValue] = useState('')
  const [timeoutMs, setTimeoutMs] = useState('8000')
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
    apiFetch('/api/clients').then((d) => {
      setClients(Array.isArray(d) ? d : d.clients || [])
    })
      // eslint-disable-next-line no-restricted-syntax -- intentional best-effort swallow
      .catch(() => {})
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
      intensity,
      ports,
      timeout_ms: Number(timeoutMs) || 8000,
      ...Object.fromEntries(
        Object.entries(toggles).map(([k, v]) => [k, typeof v === 'boolean' ? (v ? 'on' : 'off') : v]),
      ),
    }
    if (assetValue.trim()) params.asset_value = Number(assetValue)
    const body = { engine: ENGINE, target: target.trim(), params }
    if (clientId) body.client_id = Number(clientId)
    return body
  }, [intensity, ports, timeoutMs, toggles, assetValue, target, clientId])

  const hubScanParams = useMemo(() => {
    const { engine: _engine, target: _target, client_id, ...rest } = buildBody()
    return rest
  }, [buildBody])
  useSyncHubScanParams(ENGINE, hubScanParams)

  const handleRun = useCallback(async () => {
    if (!clientId) {
      showToast('error', t('pages.c2CovertExfil.select_client'))
      return
    }
    if (!target.trim()) {
      showToast('error', t('pages.c2CovertExfil.target_required'))
      return
    }
    setStatus('running')
    setFindings([])
    try {
      const { ok, data: d } = await postScan(buildBody())
      if (!ok) {
        setStatus('error')
        showToast('error', d.detail || t('pages.c2CovertExfil.scan_failed'))
        return
      }
      const jobId = d.job_id ?? ''
      showToast('info', t('pages.c2CovertExfil.queued', { id: jobId }))
      if (jobId) setPendingJobId(jobId)
      else setStatus('error')
    } catch (e) {
      setStatus('error')
      showToast('error', e?.message ?? t('pages.c2CovertExfil.scan_failed'))
    }
  }, [clientId, target, buildBody, showToast, t, postScan])

  const score = useMemo(() => extractScore(findings), [findings])
  const grade = useMemo(() => extractGrade(findings), [findings])
  const statusColor = { idle: '#475569', running: ACCENT, completed: '#4ade80', error: '#ef4444' }[status]

  return (
    <PageShell
      hideHubParams
      title={t('pages.c2CovertExfil.title')}
      badge={t('pages.c2CovertExfil.badge')}
      badgeColor={ACCENT}
      subtitle={t('pages.c2CovertExfil.subtitle')}
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
        <div className={`fixed top-16 right-4 z-50 rounded-xl border px-4 py-3 text-sm font-mono max-w-sm shadow-2xl ${toast.sev === 'error' ? 'bg-rose-950/90 border-rose-500/40 text-rose-200' : 'bg-[var(--bg-1)] border-cyan-500/30 text-cyan-200'}`}>
          {toast.msg}
        </div>
      )}

      <div className="rounded-2xl bg-[var(--bg-2)] backdrop-blur-md border border-[var(--border-default)] p-5 mb-6">
        <div className="flex flex-wrap items-end gap-4">
          <div className="flex flex-col gap-1">
            <label className="text-[10px] font-mono uppercase tracking-wider text-[var(--text-muted)]" htmlFor="c2ce-client">{t('pages.c2CovertExfil.client')}</label>
            <select id="c2ce-client" value={clientId} onChange={(e) => { setClientId(e.target.value); setTargetTouched(false) }}
              className="bg-[var(--scrim)] border border-[var(--border-default)] rounded-lg px-3 py-2 text-xs text-[var(--text-secondary)] font-mono min-w-[180px]">
              <option value="">{t('pages.c2CovertExfil.select_client_opt')}</option>
              {clients.map((c) => <option key={c.id} value={c.id}>{c.name}</option>)}
            </select>
          </div>
          <div className="flex flex-col gap-1 flex-1 min-w-[200px]">
            <label className="text-[10px] font-mono uppercase tracking-wider text-[var(--text-muted)]" htmlFor="c2ce-target">{t('pages.c2CovertExfil.target')}</label>
            <input id="c2ce-target" type="text" value={target} onChange={(e) => { setTarget(e.target.value); setTargetTouched(true) }} placeholder="https://api.example.com"
              className="bg-[var(--scrim)] border border-[var(--border-default)] rounded-lg px-3 py-2 text-xs text-[var(--text-secondary)] font-mono" />
          </div>
          <div className="flex flex-col gap-1">
            <label className="text-[10px] font-mono uppercase tracking-wider text-[var(--text-muted)]" htmlFor="c2ce-intensity">{t('pages.c2CovertExfil.intensity')}</label>
            <select id="c2ce-intensity" value={intensity} onChange={(e) => setIntensity(e.target.value)} className="bg-[var(--scrim)] border border-[var(--border-default)] rounded-lg px-3 py-2 text-xs text-[var(--text-secondary)] font-mono">
              <option value="light">light</option>
              <option value="normal">normal</option>
              <option value="aggressive">aggressive</option>
            </select>
          </div>
          <div className="flex items-center gap-2">
            <span className="w-2 h-2 rounded-full" style={{ backgroundColor: statusColor }} />
            <span className="text-[10px] font-mono text-[var(--text-muted)] uppercase">{status}</span>
          </div>
          <Button variant="unstyled" type="button" onClick={handleRun} disabled={status === 'running' || !clientId}
            className="px-5 py-2 rounded-xl font-mono text-sm border border-cyan-500/40 text-cyan-300 bg-cyan-500/10 hover:bg-cyan-500/20 disabled:opacity-40">
            {status === 'running' ? t('pages.c2CovertExfil.scanning') : t('pages.c2CovertExfil.run')}
          </Button>
          <Button variant="unstyled" type="button" onClick={() => setShowParams((s) => !s)} className="px-3 py-2 rounded-xl font-mono text-xs border border-[var(--border-default)] text-[var(--text-tertiary)]">
            {showParams ? t('pages.c2CovertExfil.hide_params') : t('pages.c2CovertExfil.show_params')}
          </Button>
        </div>

        <AnimatePresence initial={false}>
          {showParams && (
            <motion.div initial={{ height: 0, opacity: 0 }} animate={{ height: 'auto', opacity: 1 }} exit={{ height: 0, opacity: 0 }} className="overflow-hidden">
              <div className="mt-5 pt-5 border-t border-[var(--border-subtle)] grid grid-cols-1 lg:grid-cols-3 gap-6">
                <div className="grid grid-cols-1 gap-1.5 max-h-[420px] overflow-y-auto pr-1">
                  {PROBE_TOGGLES.map((tg) => (
                    <label key={tg.key} title={tg.hint} className="flex items-center gap-2 text-xs font-mono text-[var(--text-secondary)] cursor-pointer">
                      <input type="checkbox" checked={!!toggles[tg.key]} onChange={(e) => setToggles((p) => ({ ...p, [tg.key]: e.target.checked }))} className="accent-cyan-500" />
                      {tg.label}
                    </label>
                  ))}
                </div>
                <div className="space-y-3">
                  <div>
                    <label htmlFor="c2ce-ports" className="text-[10px] font-mono text-[var(--text-muted)] block mb-1">{t('pages.c2CovertExfil.extra_ports')}</label>
                    <input id="c2ce-ports" value={ports} onChange={(e) => setPorts(e.target.value)} placeholder="4443,9001" className="w-full bg-[var(--scrim)] border border-[var(--border-default)] rounded-lg px-3 py-2 text-xs font-mono text-[var(--text-secondary)]" />
                  </div>
                  <div>
                    <label htmlFor="c2ce-asset" className="text-[10px] font-mono text-[var(--text-muted)] block mb-1">{t('pages.c2CovertExfil.asset_value')}</label>
                    <input id="c2ce-asset" type="number" min={0} value={assetValue} onChange={(e) => setAssetValue(e.target.value)} placeholder="1000000" className="w-full bg-[var(--scrim)] border border-[var(--border-default)] rounded-lg px-3 py-2 text-xs font-mono text-[var(--text-secondary)]" />
                  </div>
                </div>
                <div>
                  <label htmlFor="c2ce-timeout" className="text-[10px] font-mono text-[var(--text-muted)] block mb-1">{t('pages.c2CovertExfil.timeout')}</label>
                  <input id="c2ce-timeout" type="number" min={400} max={30000} value={timeoutMs} onChange={(e) => setTimeoutMs(e.target.value)}
                    className="w-full bg-[var(--scrim)] border border-[var(--border-default)] rounded-lg px-3 py-2 text-xs font-mono text-[var(--text-secondary)]" />
                </div>
              </div>
            </motion.div>
          )}
        </AnimatePresence>
        {lastRun && <p className="text-[10px] font-mono text-[var(--text-disabled)] mt-3">{t('pages.c2CovertExfil.last_run', { time: lastRun })}</p>}
      </div>

      {findings.length > 0 && <Scorecard score={score} grade={grade} />}
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
        emptyReadyTitle={t('pages.c2CovertExfil.empty_ready_title')}
        emptyReadyBody={t('pages.c2CovertExfil.empty_ready_body')}
        renderFinding={(f, i) => <FindingCard key={i} f={f} />}
      />
    </PageShell>
  )
}
