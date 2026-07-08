import React, { useCallback, useEffect, useMemo, useRef, useState } from 'react'
import { useTranslation } from 'react-i18next'
import { Link } from 'react-router-dom'
import { createColumnHelper } from '@tanstack/react-table'
import DataTable from '../components/ui/DataTable'
import PageShell from './PageShell'
import ShellScanActions from '../components/engine/ShellScanActions'
import WeissmanListToolbar from '../components/engine/WeissmanListToolbar'
import { useFindingsWorkbench } from '../hooks/useFindingsWorkbench'
import { apiFetch } from '../lib/apiBase'
import { openSseStream, SSE_CLOSED } from '../lib/sseStream'
import { normalizeIntegrations } from '../lib/engineClientPrefill'
import { useRegisterHubClient } from '../context/EngineHubContext'
import { useClient } from '../context/ClientContext'
import { useLaunchEngineScan, useSyncHubScanParams } from '../hooks/useLaunchEngineScan'
import { useEngineScanParams } from '../hooks/useEngineScanParams'
import EngineScanParamsPanel from '../components/engine/EngineScanParamsPanel'
import EvidenceNotice from '../components/ui/EvidenceNotice'
import EmptyState from '../components/ui/EmptyState'
import ExecutiveWidget from '../components/ui/ExecutiveWidget'

const columnHelper = createColumnHelper()

const MAX_LINES = 500
const ENGINE_ID = 'osint'
const SAFE_JOB_ID_RE = /^[A-Za-z0-9._:-]+$/

const OSINT_OUTPUT_FIELDS = [
  'type',
  'source',
  'asset_type',
  'value',
  'confidence',
  'risk_impact',
  'severity',
]

function Terminal({ lines }) {
  const { t } = useTranslation()
  const ref = useRef(null)
  useEffect(() => {
    if (ref.current) ref.current.scrollTop = ref.current.scrollHeight
  }, [lines])

  return (
    <div
      ref={ref}
      className="h-72 overflow-auto rounded-xl bg-black/80 border border-white/5 p-3 font-mono text-[11px] leading-relaxed"
    >
      {lines.length === 0 ? (
        <span className="text-white/20">{t('pages.osintEngineProfile.terminal_idle')}</span>
      ) : (
        lines.map((line, i) => (
          <div
            key={i}
            className={
              line.includes('[ERROR]')
                ? 'text-red-400'
                : line.toLowerCase().includes('completed')
                  ? 'text-[#4ade80]'
                  : 'text-[#4ade80]/80'
            }
          >
            {line}
          </div>
        ))
      )}
    </div>
  )
}

export default function OsintEngineProfile() {
  const { t } = useTranslation()
  const { selectedClientId: cockpitClientId } = useClient()
  const [clients, setClients] = useState([])
  const [selectedClientId, setSelectedClientId] = useState('')
  const [target, setTarget] = useState('')
  const [running, setRunning] = useState(false)
  const [lines, setLines] = useState([])
  const [toast, setToast] = useState(null)
  const [history, setHistory] = useState(null)
  const [historyLoading, setHistoryLoading] = useState(true)
  const [clientIntegrations, setClientIntegrations] = useState(null)
  const eventSourceRef = useRef(null)
  const { schema: paramSchema, extraParams, setParam } = useEngineScanParams(ENGINE_ID, clientIntegrations)
  useRegisterHubClient(selectedClientId)
  useSyncHubScanParams(ENGINE_ID, extraParams)
  const launchScan = useLaunchEngineScan(selectedClientId)
  const closeStream = useCallback(() => {
    const es = eventSourceRef.current
    if (!es) return
    eventSourceRef.current = null
    if (es.readyState !== SSE_CLOSED) es.close()
  }, [])

  const capabilities = useMemo(
    () => [
      t('pages.osintEngineProfile.capability_1'),
      t('pages.osintEngineProfile.capability_2'),
      t('pages.osintEngineProfile.capability_3'),
      t('pages.osintEngineProfile.capability_4'),
      t('pages.osintEngineProfile.capability_5'),
    ],
    [t],
  )

  useEffect(() => {
    if (cockpitClientId) setSelectedClientId(String(cockpitClientId))
  }, [cockpitClientId])

  useEffect(() => {
    apiFetch('/api/clients')
      .then(async (r) => {
        if (!r.ok) {
          if (import.meta.env.DEV) console.warn(`[OsintEngineProfile] clients load failed: HTTP ${r.status}`)
          return []
        }
        return r.json()
      })
      .then((d) => { if (Array.isArray(d)) setClients(d) })
      .catch((err) => { if (import.meta.env.DEV) console.warn('[OsintEngineProfile] clients load failed:', err) })
  }, [])

  const loadHistory = useCallback(async () => {
    setHistoryLoading(true)
    try {
      const r = await apiFetch(`/api/engines/history/${ENGINE_ID}?limit=100`)
      const d = await r.json().catch(() => null)
      if (r.ok) setHistory(d)
    } finally {
      setHistoryLoading(false)
    }
  }, [])

  useEffect(() => {
    loadHistory()
  }, [loadHistory])

  useEffect(() => {
    if (!selectedClientId) return
    const client = clients.find((c) => String(c.id) === String(selectedClientId))
    if (!client) return
    let domains = client.domains
    if (typeof domains === 'string') {
      try { domains = JSON.parse(domains) } catch { domains = [] }
    }
    const first = Array.isArray(domains) ? (domains[0] || '') : ''
    if (first) setTarget(first.startsWith('http') ? first : `https://${first}`)
  }, [selectedClientId, clients])

  useEffect(() => {
    if (!selectedClientId) {
      setClientIntegrations(null)
      return
    }
    let cancelled = false
    apiFetch(`/api/clients/${selectedClientId}/integrations`)
      .then((r) => (r.ok ? r.json() : null))
      .then((d) => { if (!cancelled) setClientIntegrations(normalizeIntegrations(d)) })
      .catch(() => { if (!cancelled) setClientIntegrations(null) })
    return () => { cancelled = true }
  }, [selectedClientId])

  useEffect(() => () => closeStream(), [closeStream])

  const showToast = useCallback((severity, message) => {
    const id = Date.now()
    setToast({ id, severity, message })
    setTimeout(() => setToast((prev) => (prev?.id === id ? null : prev)), 5000)
  }, [])

  const selectedClientName = useMemo(
    () => clients.find((c) => String(c.id) === String(selectedClientId))?.name ?? t('pages.osintEngineProfile.no_client_selected'),
    [clients, selectedClientId, t],
  )

  const jobs = Array.isArray(history?.jobs) ? history.jobs : []
  const findings = Array.isArray(history?.findings) ? history.findings : []

  const kpi = useMemo(() => {
    const completed = jobs.filter((j) => String(j?.status || '').toLowerCase() === 'completed').length
    const running = jobs.filter((j) => String(j?.status || '').toLowerCase() === 'running').length
    const totalFindings = findings.length || jobs.reduce((sum, j) => sum + Number(j?.findings_count || 0), 0)
    return { jobs: jobs.length, completed, running, findings: totalFindings }
  }, [jobs, findings])

  const { exportCsv, filteredFindings, searchQuery, setSearchQuery } = useFindingsWorkbench(findings, { csvPrefix: 'weissman-osint' })

  const visibleFindings = useMemo(() => {
    if (!searchQuery.trim()) return findings
    const ids = new Set(filteredFindings.map((f) => String(f.id)))
    return findings.filter((f) => ids.has(String(f.id)))
  }, [findings, filteredFindings, searchQuery])

  const columns = useMemo(
    () => [
      columnHelper.accessor((f) => f.severity, {
        id: 'severity',
        header: () => t('pages.osintEngineProfile.col_severity'),
        cell: (info) => info.row.original.severity || '—',
      }),
      columnHelper.accessor((f) => f.title, {
        id: 'title',
        header: () => t('pages.osintEngineProfile.col_title'),
        cell: (info) => (
          <span className="text-white/85">{info.row.original.title || '—'}</span>
        ),
      }),
      columnHelper.accessor((f) => f.type || f.asset_type, {
        id: 'type',
        header: () => t('pages.osintEngineProfile.col_type'),
        cell: (info) => {
          const f = info.row.original
          return f.type || f.asset_type || '—'
        },
      }),
      columnHelper.accessor((f) => f.discovered_at, {
        id: 'discovered',
        header: () => t('pages.osintEngineProfile.col_discovered'),
        cell: (info) => {
          const { discovered_at: discoveredAt } = info.row.original
          return (
            <span className="text-white/50">
              {discoveredAt ? new Date(discoveredAt).toLocaleString() : '—'}
            </span>
          )
        },
      }),
    ],
    [t],
  )

  const handleRun = useCallback(async () => {
    if (!selectedClientId) {
      showToast('error', t('pages.osintEngineProfile.select_client_first'))
      return
    }
    if (!target.trim()) {
      showToast('error', t('pages.osintEngineProfile.target_required'))
      return
    }

    setRunning(true)
    setLines([])

    try {
      const { ok, data, status } = await launchScan({
        engineId: ENGINE_ID,
        clientId: selectedClientId,
        target: target.trim(),
        integrations: clientIntegrations,
        extraParams,
      })
      if (!ok) {
        showToast('error', data.detail || data.error || t('pages.osintEngineProfile.scan_failed', { status }))
        setRunning(false)
        return
      }

      const jobId = data.job_id || ''
      setLines([
        t('pages.osintEngineProfile.queued', { jobId: jobId || '(no id)' }),
        t('pages.osintEngineProfile.connecting'),
      ])
      if (!jobId) {
        setRunning(false)
        return
      }
      if (!SAFE_JOB_ID_RE.test(String(jobId))) {
        showToast('error', t('pages.osintEngineProfile.invalid_job_id'))
        setRunning(false)
        return
      }

      closeStream()
      const streamPath = `/api/telemetry/stream?job_id=${encodeURIComponent(jobId)}`
      const es = openSseStream(streamPath)
      eventSourceRef.current = es

      es.onmessage = (e) => {
        try {
          const data = JSON.parse(e.data || '{}')
          const line = data.message || data.error || ''
          if (line) {
            setLines((prev) => {
              const entry = `> ${line}`
              if (prev.length >= MAX_LINES) {
                return [...prev.slice(prev.length - MAX_LINES + 1), entry]
              }
              return [...prev, entry]
            })
          }
          if (data.status === 'completed' || data.status === 'failed') {
            setRunning(false)
            closeStream()
          }
        } catch (err) {
          if (import.meta.env.DEV) console.warn('[OsintEngineProfile] telemetry parse error:', err)
        }
      }
      es.onerror = () => {
        setRunning(false)
        closeStream()
      }
    } catch (e) {
      showToast('error', e?.message ?? t('pages.osintEngineProfile.network_error'))
      setRunning(false)
    }
  }, [closeStream, selectedClientId, target, clientIntegrations, extraParams, launchScan, showToast, t])

  return (
    <PageShell
      hideHubParams
      title={t('pages.osintEngineProfile.title')}
      subtitle={t('pages.osintEngineProfile.subtitle')}
      badge={t('pages.osintEngineProfile.badge')}
      badgeColor="#06b6d4"
      actions={(
        <ShellScanActions
          onRefresh={loadHistory}
          onExport={exportCsv}
          refreshLoading={historyLoading}
          exportDisabled={!filteredFindings.length}
        />
      )}
    >
      {toast && (
        <div
          className={`fixed top-16 right-4 z-50 rounded-xl border px-4 py-3 text-sm font-mono max-w-sm shadow-2xl ${
            toast.severity === 'error'
              ? 'bg-rose-950/90 border-rose-500/40 text-rose-200'
              : 'bg-black/80 border-cyan-500/30 text-cyan-200'
          }`}
        >
          {toast.message}
        </div>
      )}

      <EvidenceNotice>{t('pages.osintEngineProfile.evidence_notice')}</EvidenceNotice>

      <div className="grid grid-cols-2 lg:grid-cols-4 gap-3 mb-6">
        <ExecutiveWidget
          label={t('pages.osintEngineProfile.kpi_jobs')}
          value={historyLoading ? '—' : kpi.jobs.toLocaleString()}
          accent="#22d3ee"
        />
        <ExecutiveWidget
          label={t('pages.osintEngineProfile.kpi_completed')}
          value={historyLoading ? '—' : kpi.completed.toLocaleString()}
          accent="#34d399"
        />
        <ExecutiveWidget
          label={t('pages.osintEngineProfile.kpi_running')}
          value={historyLoading ? '—' : kpi.running.toLocaleString()}
          accent="#f59e0b"
        />
        <ExecutiveWidget
          label={t('pages.osintEngineProfile.kpi_findings')}
          value={historyLoading ? '—' : kpi.findings.toLocaleString()}
          accent="#a78bfa"
        />
      </div>

      {!selectedClientId && !running && (
        <EmptyState
          icon="shield"
          title={t('pages.osintEngineProfile.empty_client_title')}
          body={t('pages.osintEngineProfile.empty_client_body')}
          compact
          className="mb-6"
        />
      )}

      <section className="grid xl:grid-cols-[1.3fr_1fr] gap-6">
        <div className="space-y-6">
          <div className="rounded-2xl bg-black/40 border border-white/10 p-6 space-y-3">
            <div className="flex items-center gap-2 flex-wrap">
              <h2 className="text-2xl font-bold text-white">OSINT</h2>
              <span className="text-[10px] font-mono px-2 py-0.5 rounded border border-cyan-500/40 bg-cyan-500/10 text-cyan-300">{ENGINE_ID}</span>
              <span className="text-[10px] font-mono px-2 py-0.5 rounded border border-white/15 text-white/50">MITRE T1589</span>
            </div>
            <p className="text-sm text-white/70 leading-relaxed">
              {t('pages.osintEngineProfile.description')}
            </p>
            <div className="flex flex-wrap gap-2 text-[11px] font-mono">
              <Link to="/engines" className="px-2 py-1 rounded border border-white/10 text-white/60 hover:text-cyan-300 hover:border-cyan-500/40 transition-colors">{t('pages.osintEngineProfile.link_engine_matrix')}</Link>
              <Link to="/engine-catalog" className="px-2 py-1 rounded border border-white/10 text-white/60 hover:text-emerald-300 hover:border-emerald-500/40 transition-colors">{t('pages.osintEngineProfile.link_catalog')}</Link>
              <Link to="/threat-intel" className="px-2 py-1 rounded border border-white/10 text-white/60 hover:text-purple-300 hover:border-purple-500/40 transition-colors">{t('pages.osintEngineProfile.link_threat_intel')}</Link>
            </div>
          </div>

          <div className="rounded-2xl bg-black/40 border border-white/10 p-6">
            <h3 className="text-xs font-mono text-white/50 uppercase tracking-widest mb-4">{t('pages.osintEngineProfile.capabilities_heading')}</h3>
            <ul className="space-y-2 text-sm text-white/70">
              {capabilities.map((capability) => (
                <li key={capability} className="flex items-start gap-2">
                  <span className="text-cyan-300">•</span>
                  <span>{capability}</span>
                </li>
              ))}
            </ul>
          </div>

          <div className="rounded-2xl bg-black/40 border border-white/10 p-6">
            <h3 className="text-xs font-mono text-white/50 uppercase tracking-widest mb-4">{t('pages.osintEngineProfile.output_schema')}</h3>
            <div className="flex flex-wrap gap-2">
              {OSINT_OUTPUT_FIELDS.map((field) => (
                <span key={field} className="px-2 py-1 rounded border border-white/10 bg-white/5 text-[11px] font-mono text-white/65">
                  {field}
                </span>
              ))}
            </div>
          </div>
        </div>

        <div className="space-y-6">
          <div className="rounded-2xl bg-black/40 border border-white/10 p-6 space-y-4">
            <h3 className="text-xs font-mono text-white/50 uppercase tracking-widest">{t('pages.osintEngineProfile.run_heading')}</h3>
            <div>
              <label className="block text-[11px] font-mono text-white/50 uppercase tracking-wider mb-1">{t('pages.osintEngineProfile.client_label')}</label>
              <select
                value={selectedClientId}
                onChange={(e) => setSelectedClientId(e.target.value)}
                className="w-full bg-black/60 border border-white/10 rounded-lg px-3 py-2 text-sm text-white/90 font-mono focus:outline-none focus:border-cyan-500/40"
              >
                <option value="">{t('pages.osintEngineProfile.select_client')}</option>
                {clients.map((c) => (
                  <option key={c.id} value={c.id}>{c.name}</option>
                ))}
              </select>
              <div className="text-[10px] text-white/35 font-mono mt-1">{t('pages.osintEngineProfile.active_client', { name: selectedClientName })}</div>
            </div>
            <div>
              <label className="block text-[11px] font-mono text-white/50 uppercase tracking-wider mb-1">{t('pages.osintEngineProfile.target_label')}</label>
              <input
                type="text"
                value={target}
                onChange={(e) => setTarget(e.target.value)}
                placeholder={t('pages.osintEngineProfile.target_placeholder')}
                disabled={running}
                className="w-full bg-black/60 border border-white/10 rounded-lg px-3 py-2 text-sm text-white/90 font-mono placeholder-white/25 focus:outline-none focus:border-cyan-500/40 disabled:opacity-50"
              />
            </div>
            <EngineScanParamsPanel
              engineId={ENGINE_ID}
              schema={paramSchema}
              values={extraParams}
              onChange={setParam}
              clientId={selectedClientId}
              disabled={running}
              compact
              maxVisible={8}
            />
            <button
              type="button"
              onClick={handleRun}
              disabled={running}
              className="px-4 py-2 rounded-xl font-mono text-sm font-semibold bg-cyan-500/20 border border-cyan-500/40 text-cyan-300 hover:bg-cyan-500/30 disabled:opacity-50 disabled:cursor-not-allowed transition-all"
            >
              {running ? t('pages.osintEngineProfile.running') : t('pages.osintEngineProfile.run_btn')}
            </button>
          </div>

          <div className="rounded-2xl bg-black/40 border border-white/10 p-6 space-y-3">
            <h3 className="text-xs font-mono text-white/50 uppercase tracking-widest">{t('pages.osintEngineProfile.live_telemetry')}</h3>
            <Terminal lines={lines} />
          </div>
        </div>
      </section>

      {findings.length > 0 && (
        <section className="mt-6 rounded-2xl bg-black/40 border border-white/10 p-6 space-y-4">
          <WeissmanListToolbar
            searchQuery={searchQuery}
            onSearchChange={setSearchQuery}
            resultCount={visibleFindings.length}
            totalCount={findings.length}
          />
          {visibleFindings.length === 0 ? (
            <EmptyState
              icon="search"
              title={t('weissmanFindings.filtered_title')}
              body={t('weissmanFindings.filtered_body')}
              compact
            />
          ) : (
            <DataTable
              columns={columns}
              data={visibleFindings}
              getRowId={(f) => f.id}
              animateRows={false}
            />
          )}
        </section>
      )}
    </PageShell>
  )
}
