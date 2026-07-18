import { useCallback, useEffect, useMemo, useState } from 'react'
import { useTranslation } from 'react-i18next'
import { Link, useParams } from 'react-router-dom'
import { apiFetch } from '../utils/apiFetch'
import { buildSimpleTextPdf, downloadBytes } from '../lib/pdfExport'
import { normalizeIntegrations, TOP_TIER_PARAM_ROUTES } from '../lib/engineClientPrefill'
import { getTopTierProfile, isTopTierEngine } from '../lib/topTierEngineProfiles'
import { useEngineScanParams } from '../hooks/useEngineScanParams'
import { useCommandCenterScan } from '../hooks/useCommandCenterScan'
import { useSyncHubScanParams } from '../hooks/useLaunchEngineScan'
import EngineScanParamsPanel from '../components/engine/EngineScanParamsPanel'
import ShellScanActions from '../components/engine/ShellScanActions'
import { useFindingsWorkbench } from '../hooks/useFindingsWorkbench'
import WeissmanListToolbar from '../components/engine/WeissmanListToolbar'

import EngineHubForensicHeader from '../components/engine/EngineHubForensicHeader'
import AgentRequiredGate from '../components/engine/AgentRequiredGate'
import EmptyState from '../components/ui/EmptyState'
import { SkeletonTable } from '../components/ui/Skeleton'
import DataTable from '../components/ui/DataTable'
import { createColumnHelper } from '@tanstack/react-table'
import {
  CartesianGrid,
  Line,
  LineChart,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
  Bar,
  BarChart,
} from 'recharts'
import Button from '../components/ui/Button'

const columnHelper = createColumnHelper()

function JsonBlock({ value }) {
  return (
    <pre className="rounded-xl border border-[var(--border-default)] bg-[var(--bg-3)] p-3 text-[12px] text-emerald-300 overflow-auto font-mono">
      {JSON.stringify(value, null, 2)}
    </pre>
  )
}

export default function TopTierEngineProfile() {
  const { t } = useTranslation()
  const { engineId } = useParams()
  const profile = getTopTierProfile(engineId)
  const [audit, setAudit] = useState(null)
  const [history, setHistory] = useState(null)
  const [historyLoading, setHistoryLoading] = useState(true)
  const [clients, setClients] = useState([])
  const [clientId, setClientId] = useState('')
  const [target, setTarget] = useState('')
  const [runState, setRunState] = useState({ running: false, msg: '' })
  const [activeJobId, setActiveJobId] = useState('')
  const [liveJob, setLiveJob] = useState(null)
  const [clientIntegrations, setClientIntegrations] = useState(null)
  const { schema: paramSchema, extraParams, setParam } = useEngineScanParams(engineId, clientIntegrations)
  useSyncHubScanParams(engineId, extraParams)
  const { postScan } = useCommandCenterScan(clientId)

  const reloadAll = useCallback(async () => {
    setHistoryLoading(true)
    try {
      // allSettled so history is set whenever its call SUCCEEDS (matching the old
      // `if (historyR.ok)`), independent of body truthiness, and one call failing
      // never rejects the other. A non-JSON 2xx (raw Response) maps to null, as the
      // old `await r.json().catch(() => null)` did.
      const [auditRes, historyRes] = await Promise.allSettled([
        apiFetch('/api/engines/top-tier/audit'),
        apiFetch(`/api/engines/top-tier/${encodeURIComponent(engineId)}/history?limit=80`),
      ])
      if (auditRes.status === 'fulfilled' && Array.isArray(auditRes.value?.engines)) {
        const row = auditRes.value.engines.find((x) => x.engine_id === engineId) || null
        setAudit(row)
      }
      if (historyRes.status === 'fulfilled') {
        setHistory(historyRes.value instanceof Response ? null : historyRes.value)
      }
    } finally {
      setHistoryLoading(false)
    }
  }, [engineId])

  useEffect(() => {
    reloadAll()
  }, [reloadAll])

  useEffect(() => {
    let cancelled = false
    async function loadClients() {
      const d = await apiFetch('/api/clients').catch(() => null)
      if (!cancelled && Array.isArray(d)) setClients(d)
    }
    loadClients()
    return () => {
      cancelled = true
    }
  }, [])

  useEffect(() => {
    if (!clientId) {
      setClientIntegrations(null)
      return
    }
    let cancelled = false
    ;(async () => {
      const d = await apiFetch(`/api/clients/${clientId}/integrations`).catch(() => null)
      if (cancelled) return
      setClientIntegrations(normalizeIntegrations(d))
    })()
    return () => { cancelled = true }
  }, [clientId])

  const effectivePayload = useMemo(() => {
    const p = { engine: engineId, ...(profile?.samplePayload || {}) }
    if (clientId) p.client_id = Number(clientId)
    if (target.trim()) p.target = target.trim()
    for (const [k, v] of Object.entries(extraParams)) {
      if (v !== '' && v != null) p[k] = v
    }
    return p
  }, [profile, clientId, target, engineId, extraParams])

  const jobs = Array.isArray(history?.jobs) ? history.jobs : []
  const findings = Array.isArray(history?.findings) ? history.findings : []

  const jobListFindings = useMemo(() => jobs.map((j) => ({
    id: String(j.job_id),
    severity: String(j.status || '').toLowerCase() === 'failed' ? 'high' : 'info',
    title: String(j.job_id),
    type: j.kind || 'job',
    description: `${j.status || ''} ${j.probe_status || ''}`.trim(),
    resource: String(j.findings_count ?? ''),
  })), [jobs])

  const {
    searchQuery,
    setSearchQuery,
    filteredFindings: filteredJobFindings,
  } = useFindingsWorkbench(jobListFindings, {
    csvPrefix: `weissman-top-tier-${engineId}-jobs`,
    haystackFn: (f) => `${f.title} ${f.type} ${f.description} ${f.resource}`,
  })

  const visibleJobs = useMemo(() => {
    if (!searchQuery.trim()) return jobs
    const ids = new Set(filteredJobFindings.map((f) => String(f.id)))
    return jobs.filter((j) => ids.has(String(j.job_id)))
  }, [jobs, filteredJobFindings, searchQuery])

  const columns = useMemo(() => [
    columnHelper.accessor('job_id', {
      header: t('pages.topTierEngineProfile.col_job'),
      cell: (info) => info.row.original.job_id,
    }),
    columnHelper.accessor('kind', {
      header: t('pages.topTierEngineProfile.col_kind'),
      cell: (info) => info.row.original.kind,
    }),
    columnHelper.accessor('status', {
      header: t('pages.topTierEngineProfile.col_status'),
      cell: (info) => {
        const j = info.row.original
        return <>{j.status}{j.probe_status ? ` / ${j.probe_status}` : ''}</>
      },
    }),
    columnHelper.accessor('findings_count', {
      header: t('pages.topTierEngineProfile.col_findings'),
      cell: (info) => info.row.original.findings_count,
    }),
    columnHelper.accessor('created_at', {
      header: t('pages.topTierEngineProfile.col_created'),
      cell: (info) => info.row.original.created_at || '-',
    }),
  ], [t])

  const statusChartData = useMemo(() => {
    const tally = { completed: 0, running: 0, failed: 0, pending: 0, dead: 0 }
    for (const j of jobs) {
      const key = String(j?.status || '').toLowerCase()
      if (Object.prototype.hasOwnProperty.call(tally, key)) tally[key] += 1
    }
    return Object.entries(tally).map(([name, value]) => ({ name, value }))
  }, [jobs])

  const findingsTrendData = useMemo(() => {
    return jobs.slice(0, 12).map((j, idx) => ({
      run: `#${jobs.length - idx}`,
      findings: Number(j?.findings_count || 0),
    })).reverse()
  }, [jobs])

  useEffect(() => {
    if (!activeJobId) return undefined
    let cancelled = false
    const iv = setInterval(async () => {
      const d = await apiFetch(`/api/jobs/${encodeURIComponent(activeJobId)}`).catch(() => null)
      if (cancelled || !d) return
      setLiveJob(d)
      const status = String(d.status || '').toLowerCase()
      if (status === 'completed' || status === 'failed' || status === 'dead') {
        setRunState((prev) => ({ ...prev, running: false }))
      }
    }, 2000)
    return () => { cancelled = true; clearInterval(iv) }
  }, [activeJobId])

  async function runProbe() {
    if (!profile) return
    setRunState({ running: true, msg: t('pages.topTierEngineProfile.queueing') })
    try {
      const { ok, data: d, status } = await postScan(effectivePayload)
      if (!ok) {
        setRunState({ running: false, msg: d.detail || t('pages.topTierEngineProfile.scan_failed', { status }) })
        return
      }
      setActiveJobId(d.job_id || '')
      setLiveJob(null)
      setRunState({ running: true, msg: t('pages.topTierEngineProfile.queued_job', { jobId: d.job_id || 'unknown' }) })
    } catch (e) {
      setRunState({ running: false, msg: e?.message || t('pages.topTierEngineProfile.network_error') })
    }
  }

  async function exportJson() {
    let d
    try {
      d = await apiFetch(`/api/engines/top-tier/${encodeURIComponent(engineId)}/export?limit=120${activeJobId ? `&job_id=${encodeURIComponent(activeJobId)}` : ''}`)
    } catch (e) {
      setRunState((prev) => ({ ...prev, msg: t('pages.topTierEngineProfile.export_json_failed', { status: e?.status }) }))
      return
    }
    if (!d || d instanceof Response) {
      // non-JSON/empty 2xx (utils returns the raw Response) is a failure here,
      // not a serializable export — don't stringify a Response into a garbage file.
      setRunState((prev) => ({ ...prev, msg: t('pages.topTierEngineProfile.export_json_failed', { status: 200 }) }))
      return
    }
    const bytes = new TextEncoder().encode(JSON.stringify(d, null, 2))
    downloadBytes(bytes, `top-tier-${engineId}-export.json`, 'application/json')
  }

  function exportPdf() {
    const lines = []
    lines.push(`Top-Tier Engine Profile: ${profile.label} (${profile.id})`)
    lines.push(`Generated: ${new Date().toISOString()}`)
    lines.push(`Execution path: ${audit?.execution_path || '-'}`)
    lines.push(`Canonical: ${audit?.canonical_engine || '-'}`)
    lines.push(`Production runnable: ${audit?.is_production_runnable ? 'yes' : 'no'}`)
    lines.push('')
    lines.push('Mission')
    lines.push(profile.mission)
    lines.push('')
    lines.push('Latest jobs')
    for (const j of jobs.slice(0, 12)) {
      lines.push(`${j?.created_at || '-'} | ${j?.status || '-'} | findings=${j?.findings_count || 0} | ${j?.kind || '-'}`)
    }
    lines.push('')
    lines.push('Findings snapshot')
    for (const f of findings.slice(0, 20)) {
      lines.push(`${f?.discovered_at || '-'} | ${f?.severity || '-'} | ${f?.title || '-'}`)
    }
    if (liveJob?.id) {
      lines.push('')
      lines.push(`Active job evidence: ${liveJob.id}`)
      lines.push(`Status: ${liveJob.status || '-'}`)
      lines.push(`Attempt: ${liveJob.attempt_count || 0}`)
    }
    const bytes = buildSimpleTextPdf(lines)
    downloadBytes(bytes, `top-tier-${engineId}-export.pdf`, 'application/pdf')
  }

  if (!profile || !isTopTierEngine(engineId)) {
    return (
      <div className="min-h-[100dvh] flex flex-col items-center justify-center bg-[var(--bg-0)] text-[var(--text-tertiary)] p-8">
        <div className="text-red-400 mb-3">{t('pages.topTierEngineProfile.unknown_engine', { id: engineId })}</div>
        <Link to="/engines/top-tier" className="text-cyan-400 hover:underline">{t('pages.topTierEngineProfile.back_hub')}</Link>
      </div>
    )
  }

  return (
    <div className="min-h-[100dvh] text-[var(--text-secondary)]" style={{ background: 'var(--shell-bg)' }}>
      <header className="sticky top-0 z-20 border-b border-[var(--border-default)] bg-[var(--bg-3)] backdrop-blur-md">
        <div className="max-w-6xl mx-auto px-4 py-3 flex items-center gap-3">
          <Link to="/engines/top-tier" className="text-[var(--text-muted)] hover:text-[var(--text-secondary)] text-xs font-mono transition-colors">{t('pages.topTierEngineProfile.back_hub')}</Link>
          <span className="text-[var(--text-disabled)] text-xs">|</span>
          <Link to={`/engines/${engineId}`} className="text-cyan-400/80 hover:text-cyan-300 text-xs font-mono transition-colors">{t('pages.topTierEngineProfile.engine_detail')}</Link>
          {TOP_TIER_PARAM_ROUTES[engineId] && (
            <>
              <span className="text-[var(--text-disabled)] text-xs">|</span>
              <Link to={TOP_TIER_PARAM_ROUTES[engineId]} className="text-violet-400/80 hover:text-violet-300 text-xs font-mono transition-colors">
                {t('pages.topTierEngineProfile.command_center')}
              </Link>
            </>
          )}
          <span className="text-[var(--text-disabled)] text-xs">|</span>
          <h1 className="text-sm font-bold tracking-tight text-white">{t('pages.topTierEngineProfile.strategic_page', { label: profile.label })}</h1>
          <div className="ms-auto">
            <ShellScanActions
              onRefresh={reloadAll}
              onExport={exportJson}
              refreshLoading={historyLoading}
            />
          </div>
        </div>
      </header>

      <main className="max-w-6xl mx-auto px-4 py-6 space-y-6">
        <AgentRequiredGate engineId={engineId}>
        <EngineHubForensicHeader
          evidence={t('pages.topTierEngineProfile.evidence_notice')}
          engineId={engineId}
        />

        <section className="rounded-2xl border border-[var(--border-default)] bg-[var(--table-surface)] p-5 space-y-3">
          <div className="flex flex-wrap items-center gap-2">
            <span className="px-2 py-0.5 rounded border border-[var(--border-strong)] text-[11px] font-mono text-[var(--text-secondary)]">{profile.id}</span>
            <span className="px-2 py-0.5 rounded border border-cyan-500/30 text-[11px] font-mono text-cyan-300">MITRE {profile.mitre || 'N/A'}</span>
            <span className="px-2 py-0.5 rounded border border-amber-500/30 text-[11px] font-mono text-amber-300">{t('pages.topTierEngineProfile.top_tier_badge')}</span>
          </div>
          <p className="text-lg font-semibold text-white">{profile.mission}</p>
          <p className="text-sm text-[var(--text-tertiary)]">{profile.description}</p>
        </section>

        <section className="grid grid-cols-1 lg:grid-cols-3 gap-4">
          <article className="rounded-xl border border-[var(--border-default)] bg-[var(--bg-2)] p-4 lg:col-span-2">
            <h2 className="text-sm font-semibold text-white mb-2">{t('pages.topTierEngineProfile.deep_profile')}</h2>
            <p className="text-sm text-[var(--text-tertiary)] mb-3"><span className="text-[var(--text-secondary)]">{t('pages.topTierEngineProfile.focus')}</span> {profile.intelligenceFocus}</p>
            <div className="space-y-2">
              {profile.expectedOutputs.map((item) => (
                <div key={item} className="text-sm text-[var(--text-tertiary)]">- {item}</div>
              ))}
            </div>
          </article>
          <article className="rounded-xl border border-[var(--border-default)] bg-[var(--bg-2)] p-4">
            <h2 className="text-sm font-semibold text-white mb-2">{t('pages.topTierEngineProfile.reality_status')}</h2>
            <div className="space-y-2 text-[12px] font-mono text-[var(--text-tertiary)]">
              <div>{t('pages.topTierEngineProfile.catalog', { value: audit?.known_in_catalog ? t('pages.topTierEngineProfile.connected') : t('pages.topTierEngineProfile.missing') })}</div>
              <div>{t('pages.topTierEngineProfile.canonical', { value: audit?.canonical_engine || '-' })}</div>
              <div>{t('pages.topTierEngineProfile.execution_path', { value: audit?.execution_path || '-' })}</div>
              <div>{t('pages.topTierEngineProfile.production_runnable', { value: audit?.is_production_runnable ? t('pages.topTierEngineProfile.yes') : t('pages.topTierEngineProfile.no') })}</div>
              <div>{t('pages.topTierEngineProfile.jobs_tracked', { count: jobs.length })}</div>
              <div>{t('pages.topTierEngineProfile.findings_tracked', { count: findings.length })}</div>
            </div>
          </article>
        </section>

        <section className="rounded-xl border border-[var(--border-default)] bg-[var(--bg-2)] p-4 space-y-3">
          <h2 className="text-sm font-semibold text-white">{t('pages.topTierEngineProfile.run_live')}</h2>
          <div className="grid grid-cols-1 md:grid-cols-3 gap-3">
            <select
              value={clientId}
              onChange={(e) => setClientId(e.target.value)}
              className="bg-[var(--scrim)] border border-[var(--border-default)] rounded-lg px-3 py-2 text-sm text-[var(--text-primary)]"
            >
              <option value="">{t('pages.topTierEngineProfile.select_client')}</option>
              {clients.map((c) => (
                <option key={c.id} value={c.id}>{c.name}</option>
              ))}
            </select>
            <input
              value={target}
              onChange={(e) => setTarget(e.target.value)}
              placeholder={profile.requiresTarget ? t('pages.topTierEngineProfile.target_required') : t('pages.topTierEngineProfile.target_optional')}
              className="bg-[var(--scrim)] border border-[var(--border-default)] rounded-lg px-3 py-2 text-sm text-[var(--text-primary)]"
            />
            <Button variant="unstyled"
              type="button"
              onClick={runProbe}
              disabled={runState.running}
              className="rounded-lg px-3 py-2 text-sm font-mono border border-cyan-500/40 text-cyan-300 hover:bg-cyan-500/10 disabled:opacity-50"
            >
              {runState.running ? t('pages.topTierEngineProfile.running') : t('pages.topTierEngineProfile.queue_scan')}
            </Button>
          </div>
          {paramSchema.length > 0 && (
            <EngineScanParamsPanel
              engineId={engineId}
              schema={paramSchema}
              values={extraParams}
              onChange={setParam}
              clientId={clientId}
              disabled={runState.running}
            />
          )}
          <div className="flex flex-wrap items-center gap-2">
            <Button variant="unstyled"
              type="button"
              onClick={exportJson}
              className="rounded-lg px-3 py-1.5 text-xs font-mono border border-emerald-500/40 text-emerald-300 hover:bg-emerald-500/10"
            >
              {t('pages.topTierEngineProfile.export_json')}
            </Button>
            <Button variant="unstyled"
              type="button"
              onClick={exportPdf}
              className="rounded-lg px-3 py-1.5 text-xs font-mono border border-amber-500/40 text-amber-300 hover:bg-amber-500/10"
            >
              {t('pages.topTierEngineProfile.export_pdf')}
            </Button>
            {activeJobId && <span className="text-[11px] font-mono text-[var(--text-tertiary)]">{t('pages.topTierEngineProfile.job_id', { id: activeJobId })}</span>}
          </div>
          {runState.msg && <div className="text-[12px] font-mono text-[var(--text-tertiary)]">{runState.msg}</div>}
          {liveJob && (
            <div className="rounded-lg border border-[var(--border-default)] bg-[var(--bg-2)] p-3 text-[12px] font-mono text-[var(--text-secondary)]">
              <div>{t('pages.topTierEngineProfile.status_label', { value: liveJob.status || '-' })}</div>
              <div>{t('pages.topTierEngineProfile.attempts', { count: liveJob.attempt_count || 0 })}</div>
              <div>{t('pages.topTierEngineProfile.updated', { value: liveJob.updated_at || '-' })}</div>
              {liveJob.last_error && <div className="text-rose-300">{t('pages.topTierEngineProfile.error_label', { message: liveJob.last_error })}</div>}
              {Array.isArray(liveJob?.result?.findings) && (
                <div>{t('pages.topTierEngineProfile.live_findings', { count: liveJob.result.findings.length })}</div>
              )}
              {Array.isArray(liveJob?.result?.findings) && liveJob.result.findings.length > 0 && (
                <div className="mt-2 space-y-1">
                  {liveJob.result.findings.slice(0, 8).map((f, idx) => (
                    <div key={idx} className="text-[11px] text-[var(--text-tertiary)]">
                      - {(f?.title || f?.type || t('pages.topTierEngineProfile.finding_fallback')).toString().slice(0, 120)}
                    </div>
                  ))}
                </div>
              )}
            </div>
          )}
        </section>

        <section className="grid grid-cols-1 lg:grid-cols-2 gap-4">
          <article className="rounded-xl border border-[var(--border-default)] bg-[var(--bg-2)] p-4 h-[280px]">
            <h2 className="text-sm font-semibold text-white mb-2">{t('pages.topTierEngineProfile.job_status_chart')}</h2>
            <ResponsiveContainer width="100%" height="90%">
              <BarChart accessibilityLayer data={statusChartData}>
                <CartesianGrid strokeDasharray="3 3" stroke="#334155" />
                <XAxis dataKey="name" stroke="#94a3b8" />
                <YAxis stroke="#94a3b8" allowDecimals={false} />
                <Tooltip />
                <Bar dataKey="value" fill="#22d3ee" />
              </BarChart>
            </ResponsiveContainer>
          </article>
          <article className="rounded-xl border border-[var(--border-default)] bg-[var(--bg-2)] p-4 h-[280px]">
            <h2 className="text-sm font-semibold text-white mb-2">{t('pages.topTierEngineProfile.findings_trend')}</h2>
            <ResponsiveContainer width="100%" height="90%">
              <LineChart accessibilityLayer data={findingsTrendData}>
                <CartesianGrid strokeDasharray="3 3" stroke="#334155" />
                <XAxis dataKey="run" stroke="#94a3b8" />
                <YAxis stroke="#94a3b8" allowDecimals={false} />
                <Tooltip />
                <Line type="monotone" dataKey="findings" stroke="#4ade80" strokeWidth={2} dot={{ r: 2 }} />
              </LineChart>
            </ResponsiveContainer>
          </article>
        </section>

        <section className="grid grid-cols-1 lg:grid-cols-2 gap-4">
          <article className="rounded-xl border border-[var(--border-default)] bg-[var(--bg-2)] p-4">
            <h2 className="text-sm font-semibold text-white mb-2">{t('pages.topTierEngineProfile.sample_payload')}</h2>
            <JsonBlock value={effectivePayload} />
          </article>
          <article className="rounded-xl border border-[var(--border-default)] bg-[var(--bg-2)] p-4">
            <h2 className="text-sm font-semibold text-white mb-2">{t('pages.topTierEngineProfile.operator_notes')}</h2>
            <div className="space-y-2 text-sm text-[var(--text-tertiary)]">
              <div>{t('pages.topTierEngineProfile.note_tactical')}</div>
              <div>{t('pages.topTierEngineProfile.note_catalog')}</div>
              <div>{t('pages.topTierEngineProfile.note_monitor')}</div>
              <div>{t('pages.topTierEngineProfile.note_triage')}</div>
            </div>
          </article>
        </section>

        <section className="rounded-xl border border-[var(--border-default)] bg-[var(--bg-2)] p-4 space-y-3">
          <h2 className="text-sm font-semibold text-white">{t('pages.topTierEngineProfile.recent_jobs')}</h2>
          {jobs.length > 0 && (
            <WeissmanListToolbar
              searchQuery={searchQuery}
              onSearchChange={setSearchQuery}
              resultCount={visibleJobs.length}
              totalCount={jobs.length}
            />
          )}
          {historyLoading ? (
            <SkeletonTable rows={8} cols={5} />
          ) : jobs.length === 0 ? (
            <EmptyState
              icon="inbox"
              title={t('pages.topTierEngineProfile.empty_jobs_title')}
              body={t('pages.topTierEngineProfile.empty_jobs_body')}
              compact
            />
          ) : visibleJobs.length === 0 ? (
            <EmptyState
              icon="search"
              title={t('weissmanFindings.filtered_title')}
              body={t('weissmanFindings.filtered_body')}
              compact
            />
          ) : (
          <DataTable
            columns={columns}
            data={visibleJobs.slice(0, 20)}
            animateRows={false}
            getRowId={(j) => `${j.job_id}-${j.created_at}`}
          />
          )}
        </section>
        </AgentRequiredGate>
      </main>
    </div>
  )
}
