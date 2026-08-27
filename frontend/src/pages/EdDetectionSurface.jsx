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
import { useJobPoll, resolveJobFindings, extractFindingsFromJob, uiJobStatus } from '../lib/useJobPoll'
import Button from '../components/ui/Button'
import ScopedClientControl from '../components/clients/ScopedClientControl'


const ENGINE = 'edr_evasion'
const ACCENT = '#a855f7'

const PROBE_TOGGLES = [
  { key: 'check_waf', label: 'WAF / CDN fingerprint', hint: 'Cloudflare, Akamai, AWS WAF, Imperva, DataDome, PerimeterX', defaultVal: true },
  { key: 'check_ua_matrix', label: 'Scanner UA block matrix', hint: 'sqlmap, Nikto, nmap, bots — block-rate score', defaultVal: true },
  { key: 'check_rate_limit', label: 'Rate-limit burst', hint: '429/503 + Retry-After under burst', defaultVal: true },
  { key: 'check_headers', label: 'Security headers', hint: 'X-Content-Type-Options, COOP, Permissions-Policy', defaultVal: true },
  { key: 'check_cookies', label: 'Cookie hardening', hint: 'Secure / HttpOnly / SameSite on Set-Cookie', defaultVal: true },
  { key: 'check_csp', label: 'CSP injection runway', hint: 'unsafe-inline, unsafe-eval, wildcard connect-src', defaultVal: true },
  { key: 'check_telemetry', label: 'Defender telemetry in page', hint: 'Sentry, Datadog, New Relic, Segment keys in HTML', defaultVal: true },
  { key: 'check_debug_paths', label: 'Debug / admin paths', hint: 'actuator, .env, swagger, .git/HEAD', defaultVal: true },
  { key: 'check_source_maps', label: 'JS source maps', hint: '.map files with mappings/sources', defaultVal: true },
  { key: 'check_error_verbosity', label: 'Verbose errors', hint: 'Stack traces on malformed requests', defaultVal: true },
  { key: 'include_agent_findings', label: 'Host EDR agent guidance', hint: 'Honest info row for AMSI/ETW/syscall tests', defaultVal: true },
]

const DEFAULT_PARAMS = {
  intensity: 'normal',
  timeout_ms: 8000,
  ua_matrix_limit: 24,
  rate_burst_count: 12,
  extra_paths: '',
  ...Object.fromEntries(PROBE_TOGGLES.map((t) => [t.key, t.defaultVal])),
}

const SEV_STYLE = {
  critical: { text: 'text-rose-300', bd: 'border-rose-500/40', bg: 'bg-rose-500/10' },
  high: { text: 'text-orange-300', bd: 'border-orange-500/40', bg: 'bg-orange-500/10' },
  medium: { text: 'text-amber-300', bd: 'border-amber-500/40', bg: 'bg-amber-500/10' },
  low: { text: 'text-sky-300', bd: 'border-sky-500/40', bg: 'bg-sky-500/10' },
  info: { text: 'text-[var(--text-secondary)]', bd: 'border-[var(--border-default)]', bg: 'bg-[var(--row-hover-bg)]' },
}

function scoreColor(score) {
  if (score >= 80) return '#34d399'
  if (score >= 60) return '#a3e635'
  if (score >= 40) return '#fbbf24'
  if (score >= 20) return '#fb923c'
  return '#fb7185'
}

function isSummary(f) {
  return typeof f?.title === 'string' && f.title.includes('Detection resilience score')
}

function extractScore(findings) {
  const s = findings.find(isSummary)
  if (!s) return null
  const fromEv = s.evidence?.detection_resilience_score
  if (fromEv != null) return Number(fromEv)
  const m = s.title.match(/score:\s*(\d+)/i)
  return m ? Number(m[1]) : null
}


function Toggle({ label, hint, checked, onChange }) {
  return (
    <Button variant="unstyled" type="button" role="switch" aria-checked={checked} onClick={() => onChange(!checked)} className="w-full flex items-center justify-between gap-3 px-3 py-2 rounded-lg bg-[var(--row-hover-bg)] border border-[var(--border-subtle)] hover:bg-[var(--row-hover-bg)] transition-all text-left">
      <span className="min-w-0">
        <span className="block text-[12px] font-mono text-[var(--text-primary)] truncate">{label}</span>
        {hint && <span className="block text-[10px] font-mono text-[var(--text-muted)] truncate">{hint}</span>}
      </span>
      <span className={`shrink-0 w-9 h-5 rounded-full relative transition-colors ${checked ? 'bg-violet-500/70' : 'bg-white/15'}`}>
        <span className={`absolute top-0.5 w-4 h-4 rounded-full bg-white transition-all ${checked ? 'left-[18px]' : 'left-0.5'}`} />
      </span>
    </Button>
  )
}

function FindingCard({ f }) {
  const [open, setOpen] = useState(false)
  const sev = (f.severity || 'info').toLowerCase()
  const style = SEV_STYLE[sev] || SEV_STYLE.info
  return (
    <div className={`rounded-xl border ${style.bd} ${style.bg} overflow-hidden`}>
      <Button variant="unstyled" type="button" onClick={() => setOpen((o) => !o)} className="w-full flex items-start gap-3 px-3 py-2.5 text-left hover:bg-[var(--row-hover-bg)]">
        <span className={`text-[9px] font-mono px-1.5 py-0.5 rounded border uppercase ${style.text} ${style.bd}`}>{sev}</span>
        <span className="min-w-0 flex-1 text-[12px] font-mono text-[var(--text-primary)]">{f.title || f.type}</span>
        <span className="text-[var(--text-disabled)] text-xs">{open ? '▾' : '▸'}</span>
      </Button>
      <AnimatePresence initial={false}>
        {open && (
          <motion.div initial={{ height: 0, opacity: 0 }} animate={{ height: 'auto', opacity: 1 }} exit={{ height: 0, opacity: 0 }} className="px-3 pb-3">
            <p className="text-[11px] font-mono text-[var(--text-tertiary)] leading-relaxed">{f.description}</p>
            {f.evidence && (
              <pre className="mt-2 text-[10px] font-mono text-[var(--text-muted)] overflow-x-auto bg-[var(--bg-2)] rounded p-2">{JSON.stringify(f.evidence, null, 2)}</pre>
            )}
          </motion.div>
        )}
      </AnimatePresence>
    </div>
  )
}

export default function EdDetectionSurface() {
  const { t } = useTranslation()
  const [clients, setClients] = useState([])
  const [selectedClientId, setSelectedClientId] = useState(null)
  const { postScan } = useCommandCenterScan(selectedClientId)
  const [target, setTarget] = useState('')
  const [params, setParams] = useState(DEFAULT_PARAMS)
  useSyncHubScanParams(ENGINE, params)
  const [scanning, setScanning] = useState(false)
  const [pendingJobId, setPendingJobId] = useState(null)
  const [findings, setFindings] = useState([])

  useEffect(() => {
    // eslint-disable-next-line no-restricted-syntax -- intentional best-effort swallow
    apiFetch('/api/clients').then((d) => { if (Array.isArray(d)) setClients(d) }).catch(() => {})
  }, [])

  useEffect(() => {
    if (!selectedClientId) return
    const client = clients.find((c) => String(c.id) === String(selectedClientId))
    const host = firstClientTarget(client)
    if (host) setTarget(host)
  }, [selectedClientId, clients])

  const setParam = useCallback((key, val) => setParams((p) => ({ ...p, [key]: val })), [])

  const score = useMemo(() => extractScore(findings), [findings])
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
      const resolved = await resolveJobFindings(job, ENGINE, selectedClientId)
      const fromJob = extractFindingsFromJob(job)
      setFindings(resolved.length ? resolved : fromJob)
      setLastUpdated(new Date().toISOString())
      if (pendingJobId) setLastJobId(pendingJobId)
      setScanning(false)
      setPendingJobId(null)
    },
  })

  const handleScan = useCallback(async () => {
    if (!selectedClientId || !target.trim()) return
    setScanning(true)
    setFindings([])
    const body = {
      engine: ENGINE,
      client_id: Number(selectedClientId),
      target: target.includes('://') ? target.trim() : `https://${target.trim()}`,
    }
    for (const [k, v] of Object.entries(params)) {
      if (typeof v === 'boolean') body[k] = v ? 'true' : 'false'
      else if (v !== '' && v != null) body[k] = v
    }
    try {
      const { ok, data: d } = await postScan(body)
      if (!ok) { setScanning(false); return }
      if (d.job_id) setPendingJobId(d.job_id)
      else setScanning(false)
    } catch {
      setScanning(false)
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [selectedClientId, target, params])

  const jobStatus = uiJobStatus(pendingJobId, scanning)

  return (
    <PageShell
      hideHubParams
      title={t('pages.edDetection.title')}
      badge={t('pages.edDetection.badge')}
      badgeColor={ACCENT}
      subtitle={t('pages.edDetection.subtitle')}
      actions={(
        <ShellScanActions
          onRefresh={handleRefresh}
          onExport={exportCsv}
          refreshLoading={historyLoading}
          refreshDisabled={scanning}
          exportDisabled={!filteredFindings.length}
        />
      )}
    >
      <div className="flex flex-wrap items-center gap-3 mb-6">
        <ScopedClientControl
              value={selectedClientId ?? ''}
              onChange={(id) => setSelectedClientId(id || null)}
              clients={clients}
              className="bg-[var(--scrim)] border border-[var(--border-default)] rounded-lg px-3 py-1.5 text-xs font-mono text-[var(--text-secondary)]"
              placeholder={t('pages.edDetection.select_client')}
              allowEmpty
            />
        <input type="text" value={target} onChange={(e) => setTarget(e.target.value)} placeholder={t('pages.edDetection.target_placeholder')} className="flex-1 min-w-[200px] bg-[var(--scrim)] border border-[var(--border-default)] rounded-lg px-3 py-1.5 text-xs font-mono text-[var(--text-primary)]" />
        <Button variant="unstyled" type="button" onClick={handleScan} disabled={scanning || !selectedClientId} className="px-5 py-2 rounded-xl font-mono text-sm border border-violet-500/40 text-violet-300 bg-violet-500/10 hover:bg-violet-500/20 disabled:opacity-40">
          {scanning ? t('pages.edDetection.scanning') : t('pages.edDetection.run_scan')}
        </Button>
        {jobStatus && <span className="text-[10px] font-mono text-[var(--text-muted)]">{jobStatus}</span>}
      </div>

      <div className="grid grid-cols-1 xl:grid-cols-3 gap-6">
        <motion.section initial={{ opacity: 0, y: 8 }} animate={{ opacity: 1, y: 0 }} className="rounded-2xl bg-[var(--bg-2)] border border-[var(--border-default)] p-5 space-y-4 max-h-[85vh] overflow-y-auto">
          <h3 className="text-xs font-mono text-[var(--text-tertiary)] uppercase tracking-widest">{t('pages.edDetection.control_panel')}</h3>
          <select value={params.intensity} onChange={(e) => setParam('intensity', e.target.value)} className="w-full bg-[var(--bg-3)] border border-[var(--border-default)] rounded-md px-2 py-1.5 text-[11px] font-mono text-[var(--text-secondary)]">
            <option value="light">{t('pages.edDetection.intensity_light')}</option>
            <option value="normal">{t('pages.edDetection.intensity_normal')}</option>
            <option value="aggressive">{t('pages.edDetection.intensity_aggressive')}</option>
          </select>
          <div className="grid grid-cols-2 gap-3">
            <label className="text-[10px] font-mono text-[var(--text-muted)]">{t('pages.edDetection.ua_limit')}
              <input type="number" min={4} max={80} value={params.ua_matrix_limit} onChange={(e) => setParam('ua_matrix_limit', Number(e.target.value))} className="mt-1 w-full bg-[var(--bg-3)] border border-[var(--border-default)] rounded-md px-2 py-1 text-[11px] font-mono text-[var(--text-secondary)]" />
            </label>
            <label className="text-[10px] font-mono text-[var(--text-muted)]">{t('pages.edDetection.rate_burst')}
              <input type="number" min={3} max={40} value={params.rate_burst_count} onChange={(e) => setParam('rate_burst_count', Number(e.target.value))} className="mt-1 w-full bg-[var(--bg-3)] border border-[var(--border-default)] rounded-md px-2 py-1 text-[11px] font-mono text-[var(--text-secondary)]" />
            </label>
          </div>
          <input type="text" value={params.extra_paths} onChange={(e) => setParam('extra_paths', e.target.value)} placeholder="/admin,/internal" className="w-full bg-[var(--bg-3)] border border-[var(--border-default)] rounded-md px-2 py-1.5 text-[11px] font-mono text-[var(--text-secondary)]" />
          <div className="space-y-2 pt-2 border-t border-[var(--border-subtle)]">
            {PROBE_TOGGLES.map((tog) => (
              <Toggle key={tog.key} label={tog.label} hint={tog.hint} checked={Boolean(params[tog.key])} onChange={(v) => setParam(tog.key, v)} />
            ))}
          </div>
        </motion.section>

        <div className="xl:col-span-2 space-y-6">
          <motion.section initial={{ opacity: 0, y: 8 }} animate={{ opacity: 1, y: 0 }} className="rounded-2xl bg-[var(--bg-2)] border border-[var(--border-default)] p-6 flex flex-wrap items-center gap-8">
            <div className="text-center min-w-[120px]">
              <p className="text-[10px] font-mono text-[var(--text-muted)] uppercase mb-2">{t('pages.edDetection.resilience_score')}</p>
              <p className="text-5xl font-bold font-mono" style={{ color: scoreColor(score ?? 0) }}>{score ?? '—'}</p>
              <p className="text-[10px] font-mono text-[var(--text-muted)] mt-1">{t('pages.edDetection.score_hint')}</p>
            </div>
            <div className="flex-1 min-w-[200px] text-[11px] font-mono text-[var(--text-tertiary)] leading-relaxed">{t('pages.edDetection.score_explainer')}</div>
          </motion.section>

          <WeissmanFindingsPanel
            findings={detailFindings}
            filteredFindings={filteredFindings}
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
            accent={ACCENT}
            showEmptyReady={!scanning && detailFindings.length === 0}
            emptyReadyTitle={t('pages.edDetection.empty_ready')}
            emptyReadyBody={t('pages.edDetection.empty_ready')}
            renderFinding={(f, i) => <FindingCard key={i} f={f} />}
          />
        </div>
      </div>
    </PageShell>
  )
}
