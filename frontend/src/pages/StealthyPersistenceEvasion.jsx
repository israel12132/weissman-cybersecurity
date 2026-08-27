import { firstClientTarget } from '../lib/clientTarget'
import { useCommandCenterScan } from '../hooks/useCommandCenterScan'
import { useSyncHubScanParams } from '../hooks/useLaunchEngineScan'
import { useState, useEffect, useCallback, useMemo } from 'react'
import { useTranslation } from 'react-i18next'
import { motion } from 'framer-motion'
import PageShell from './PageShell'
import ShellScanActions from '../components/engine/ShellScanActions'
import WeissmanFindingsPanel from '../components/engine/WeissmanFindingsPanel'
import { useWeissmanEnginePage, applyHistoryFindings } from '../hooks/useWeissmanEnginePage'
import { apiFetch } from '../utils/apiFetch'
import { useJobPoll, resolveJobFindings, extractFindingsFromJob, uiJobStatus } from '../lib/useJobPoll'
import Button from '../components/ui/Button'
import EvidenceNotice from '../components/ui/EvidenceNotice'

export const ENGINE = 'stealthy_persistence_evasion'
const ACCENT = '#22d3ee'

export function scoreFromFindings(findings) {
  const s = (Array.isArray(findings) ? findings : []).find((f) =>
    String(f?.title || '').includes('Intelligence-grade evasion score'),
  )
  const fromEv = s?.evidence?.intelligence_grade_evasion_score
  if (fromEv != null) return Number(fromEv)
  const m = String(s?.title || '').match(/score:\s*(\d+)/i)
  return m ? Number(m[1]) : null
}

export function domainRows(findings) {
  return (Array.isArray(findings) ? findings : []).filter((f) =>
    String(f?.title || '').startsWith('Domain '),
  )
}

export function catalogSearchRows(checks, query) {
  const q = String(query || '').trim().toLowerCase()
  const list = Array.isArray(checks) ? checks : []
  if (!q) return list
  return list.filter((c) =>
    [c.id, c.title, c.mitre, c.domain].join(' ').toLowerCase().includes(q),
  )
}

function scoreColor(score) {
  if (score >= 80) return '#34d399'
  if (score >= 60) return '#a3e635'
  if (score >= 40) return '#fbbf24'
  if (score >= 20) return '#fb923c'
  return '#fb7185'
}

export default function StealthyPersistenceEvasion() {
  const { t } = useTranslation()
  const [clients, setClients] = useState([])
  const [selectedClientId, setSelectedClientId] = useState(null)
  const { postScan } = useCommandCenterScan(selectedClientId)
  const [target, setTarget] = useState('')
  const [params, setParams] = useState({ intensity: 'normal', safe_mode: true })
  useSyncHubScanParams(ENGINE, params)
  const [scanning, setScanning] = useState(false)
  const [pendingJobId, setPendingJobId] = useState(null)
  const [findings, setFindings] = useState([])
  const [catalog, setCatalog] = useState({ checks: [], domains: [], catalog_len: 500 })
  const [status, setStatus] = useState(null)
  const [statusErr, setStatusErr] = useState('')
  const [catalogQuery, setCatalogQuery] = useState('')
  const [wiping, setWiping] = useState(false)
  const [wipeMsg, setWipeMsg] = useState(null)

  useEffect(() => {
    apiFetch('/api/clients').then((d) => { if (Array.isArray(d)) setClients(d) }).catch(() => {})
    apiFetch('/api/stealthy-persistence-evasion/catalog')
      .then((d) => { if (d?.checks) setCatalog(d) })
      .catch(() => {})
  }, [])

  const loadStatus = useCallback(async () => {
    try {
      const q = selectedClientId ? `?client_id=${encodeURIComponent(selectedClientId)}` : ''
      const d = await apiFetch(`/api/stealthy-persistence-evasion/status${q}`)
      setStatus(d)
      setStatusErr('')
    } catch (e) {
      setStatusErr((e && e.message) || 'status failed')
    }
  }, [selectedClientId])

  useEffect(() => { loadStatus() }, [loadStatus])

  useEffect(() => {
    if (!selectedClientId) return
    const client = clients.find((c) => String(c.id) === String(selectedClientId))
    const host = firstClientTarget(client)
    if (host) setTarget(host)
  }, [selectedClientId, clients])

  const score = useMemo(() => scoreFromFindings(findings), [findings])
  const domains = useMemo(() => domainRows(findings), [findings])
  const catalogHits = useMemo(
    () => catalogSearchRows(catalog.checks, catalogQuery),
    [catalog.checks, catalogQuery],
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
  } = useWeissmanEnginePage(ENGINE, findings)

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
    await loadStatus()
  }, [refreshFromHistory, setLastUpdated, setLastJobId, loadStatus])

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
      loadStatus()
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
      intensity: params.intensity,
      safe_mode: params.safe_mode ? 'true' : 'false',
    }
    try {
      const { ok, data: d } = await postScan(body)
      if (!ok) { setScanning(false); return }
      if (d.job_id) setPendingJobId(d.job_id)
      else setScanning(false)
    } catch {
      setScanning(false)
    }
  }, [selectedClientId, target, params, postScan])

  const handleFailSafe = useCallback(async () => {
    setWiping(true)
    setWipeMsg(null)
    try {
      const d = await apiFetch('/api/stealthy-persistence-evasion/fail-safe', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          client_id: selectedClientId ? Number(selectedClientId) : undefined,
          reason: 'command-center fail-safe',
        }),
      })
      setWipeMsg(d)
      await loadStatus()
    } catch (e) {
      setWipeMsg({ ok: false, error: (e && e.message) || 'wipe failed' })
    } finally {
      setWiping(false)
    }
  }, [selectedClientId, loadStatus])

  const jobStatus = uiJobStatus(pendingJobId, scanning)
  const cp = status?.control_plane || {}

  return (
    <PageShell
      hideHubParams
      hideEvidence
      engineId={ENGINE}
      title={t('pages.stealthyEvasion.title')}
      badge={t('pages.stealthyEvasion.badge')}
      badgeColor={ACCENT}
      subtitle={t('pages.stealthyEvasion.subtitle')}
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
      <EvidenceNotice className="mb-4">
        {t('pages.stealthyEvasion.evidence_notice')}
      </EvidenceNotice>

      <div className="flex flex-wrap items-center gap-3 mb-6">
        <select
          value={selectedClientId ?? ''}
          onChange={(e) => setSelectedClientId(e.target.value || null)}
          className="bg-[var(--scrim)] border border-[var(--border-default)] rounded-lg px-3 py-1.5 text-xs font-mono text-[var(--text-secondary)]"
        >
          <option value="">{t('pages.stealthyEvasion.select_client')}</option>
          {clients.map((c) => <option key={c.id} value={c.id}>{c.name}</option>)}
        </select>
        <input
          type="text"
          value={target}
          onChange={(e) => setTarget(e.target.value)}
          placeholder={t('pages.stealthyEvasion.target_placeholder')}
          className="flex-1 min-w-[200px] bg-[var(--scrim)] border border-[var(--border-default)] rounded-lg px-3 py-1.5 text-xs font-mono text-[var(--text-primary)]"
        />
        <select
          value={params.intensity}
          onChange={(e) => setParams((p) => ({ ...p, intensity: e.target.value }))}
          className="bg-[var(--scrim)] border border-[var(--border-default)] rounded-lg px-3 py-1.5 text-xs font-mono text-[var(--text-secondary)]"
        >
          <option value="light">{t('pages.stealthyEvasion.intensity_light')}</option>
          <option value="normal">{t('pages.stealthyEvasion.intensity_normal')}</option>
          <option value="aggressive">{t('pages.stealthyEvasion.intensity_aggressive')}</option>
        </select>
        <Button
          variant="unstyled"
          type="button"
          onClick={handleScan}
          disabled={scanning || !selectedClientId}
          className="px-5 py-2 rounded-xl font-mono text-sm border border-cyan-500/40 text-cyan-300 bg-cyan-500/10 hover:bg-cyan-500/20 disabled:opacity-40"
        >
          {scanning ? t('pages.stealthyEvasion.scanning') : t('pages.stealthyEvasion.run_scan')}
        </Button>
        <Button
          variant="unstyled"
          type="button"
          onClick={handleFailSafe}
          disabled={wiping}
          className="px-4 py-2 rounded-xl font-mono text-sm border border-rose-500/40 text-rose-300 bg-rose-500/10 hover:bg-rose-500/20 disabled:opacity-40"
        >
          {wiping ? t('pages.stealthyEvasion.wiping') : t('pages.stealthyEvasion.fail_safe')}
        </Button>
        {jobStatus && <span className="text-[10px] font-mono text-[var(--text-muted)]">{jobStatus}</span>}
        {lastUpdated && <span className="text-[10px] font-mono text-[var(--text-muted)]">{lastUpdated}</span>}
      </div>

      {statusErr && (
        <div className="rounded-lg border border-rose-500/40 bg-rose-950/30 px-4 py-3 text-sm text-rose-300 mb-4">{statusErr}</div>
      )}
      {wipeMsg && (
        <div className={`rounded-lg border px-4 py-3 text-sm font-mono mb-4 ${wipeMsg.ok ? 'border-emerald-500/40 text-emerald-300' : 'border-rose-500/40 text-rose-300'}`}>
          {wipeMsg.ok ? t('pages.stealthyEvasion.wipe_ok', { n: wipeMsg.agents_signaled ?? 0 }) : (wipeMsg.error || 'fail-safe error')}
        </div>
      )}

      <div className="grid grid-cols-2 md:grid-cols-4 xl:grid-cols-6 gap-3 mb-6">
        <Stat label={t('pages.stealthyEvasion.score')} value={score == null ? '—' : `${score}`} color={score == null ? undefined : scoreColor(score)} />
        <Stat label={t('pages.stealthyEvasion.checks')} value={catalog.catalog_len ?? 500} />
        <Stat label="RLS" value={cp.rls_policy_count ?? '—'} />
        <Stat label="COPY" value={cp.copy_ingest_ok ? 'live' : '—'} />
        <Stat label="SKIP LOCKED" value={cp.skip_locked_claim ? 'ok' : '—'} />
        <Stat label="CI" value={`${cp.ci_scripts_present ?? 0}/5`} />
      </div>

      {domains.length > 0 && (
        <div className="grid grid-cols-1 md:grid-cols-2 xl:grid-cols-5 gap-3 mb-6">
          {domains.map((d) => (
            <motion.div
              key={d.title}
              initial={{ opacity: 0, y: 6 }}
              animate={{ opacity: 1, y: 0 }}
              className="rounded-xl border border-[var(--border-default)] bg-[var(--bg-2)] p-3"
            >
              <div className="text-[10px] font-mono text-[var(--text-muted)] uppercase tracking-widest truncate">{d.title}</div>
              <div className="text-lg font-mono tabular-nums mt-1" style={{ color: scoreColor(Number(d.evidence?.score ?? 0)) }}>
                {d.evidence?.score != null ? `${d.evidence.score}/100` : d.severity}
              </div>
              <div className="text-[11px] font-mono text-[var(--text-secondary)] mt-0.5">
                {d.evidence?.gaps != null ? `${d.evidence.gaps} gaps · |z|=${Number(d.evidence.z_abs || 0).toFixed(2)}` : d.severity}
              </div>
            </motion.div>
          ))}
        </div>
      )}

      <div className="grid grid-cols-1 xl:grid-cols-3 gap-6">
        <section className="rounded-2xl bg-[var(--bg-2)] border border-[var(--border-default)] p-5 space-y-3 max-h-[70vh] overflow-y-auto">
          <h3 className="text-xs font-mono text-[var(--text-tertiary)] uppercase tracking-widest">
            {t('pages.stealthyEvasion.catalog')}
          </h3>
          <input
            type="search"
            value={catalogQuery}
            onChange={(e) => setCatalogQuery(e.target.value)}
            placeholder={t('pages.stealthyEvasion.search_checks')}
            className="w-full bg-[var(--bg-3)] border border-[var(--border-default)] rounded-md px-2 py-1.5 text-[11px] font-mono text-[var(--text-secondary)]"
          />
          <div className="text-[10px] font-mono text-[var(--text-muted)]">
            {catalogHits.length}/{catalog.checks?.length || 0}
          </div>
          <ul className="space-y-1">
            {catalogHits.slice(0, 80).map((c) => (
              <li key={c.id} className="text-[11px] font-mono text-[var(--text-secondary)] border-b border-[var(--border-subtle)] py-1">
                <span className="text-cyan-400/80">{String(c.id).padStart(3, '0')}</span>
                {' '}{c.title}
                <span className="text-[var(--text-muted)]"> · {c.mitre}</span>
              </li>
            ))}
          </ul>
        </section>
        <section className="xl:col-span-2 rounded-2xl bg-[var(--bg-2)] border border-[var(--border-default)] p-5">
          <WeissmanFindingsPanel
            findings={findings}
            filteredFindings={filteredFindings}
            counts={counts}
            total={findings.length}
            searchQuery={searchQuery}
            onSearchChange={setSearchQuery}
            severityFilter={severityFilter}
            onSeverityChange={setSeverityFilter}
            pending={scanning && findings.length === 0}
            loading={historyLoading && findings.length === 0}
            lastUpdated={lastUpdated}
            jobId={pendingJobId || lastJobId}
            accent={ACCENT}
            showEmptyReady={!scanning && findings.length === 0}
            emptyReadyTitle={t('pages.stealthyEvasion.empty_ready')}
            emptyReadyBody={t('pages.stealthyEvasion.empty_ready')}
          />
        </section>
      </div>
    </PageShell>
  )
}

function Stat({ label, value, color }) {
  return (
    <div className="rounded-lg border border-[var(--border-default)] bg-[var(--bg-2)] px-3 py-2.5">
      <div className="text-[10px] uppercase tracking-wider text-[var(--text-muted)]">{label}</div>
      <div className="text-xl font-semibold tabular-nums font-mono" style={color ? { color } : undefined}>{value}</div>
    </div>
  )
}
