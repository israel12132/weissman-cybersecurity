import { useEffect, useState, useCallback, useRef, useMemo } from 'react'
import { Link } from 'react-router'
import { useTranslation } from 'react-i18next'
import { Search, Briefcase, AlertTriangle, ShieldAlert, Bot } from 'lucide-react'
import { createColumnHelper } from '@tanstack/react-table'
import PageShell from './PageShell'
import ShellScanActions from '../components/engine/ShellScanActions'
import { useFindingsWorkbench } from '../hooks/useFindingsWorkbench'
import EmptyState from '../components/ui/EmptyState'
import DataTable from '../components/ui/DataTable'
import { SkeletonTable, SkeletonWidgetGrid } from '../components/ui/Skeleton'
import CopyButton, { CopyableField } from '../components/ui/CopyButton'
import { apiFetch } from '../utils/apiFetch'
import { useVisiblePolling } from '../hooks/useVisiblePolling'
import { useAuth } from '../context/AuthContext'
import Button from '../components/ui/Button'
import {
  TILE_STATES,
  operatorState,
  operatorBadgeClass,
  operatorStateCounts,
  matchesOperatorFilter,
  remapLabel,
  diagnosticsHaystack,
  JOBS_CSV_HEADER,
  jobToCsvRow,
  mergeJobDiagnostics,
  leaseOwner,
} from '../lib/jobDiagnostics'

const columnHelper = createColumnHelper()

const FILTER_KEYS = ['all', ...TILE_STATES]

function exportJobsCsv(jobs) {
  const esc = (v) => `"${String(v ?? '').replace(/"/g, '""')}"`
  const lines = [
    JOBS_CSV_HEADER.join(','),
    ...jobs.map((j) => jobToCsvRow(j).map(esc).join(',')),
  ]
  const blob = new Blob([lines.join('\n')], { type: 'text/csv;charset=utf-8' })
  const url = URL.createObjectURL(blob)
  const a = document.createElement('a')
  a.href = url
  a.download = `weissman-jobs-${new Date().toISOString().slice(0, 10)}.csv`
  a.click()
  URL.revokeObjectURL(url)
}

export default function JobsDashboard() {
  const { t, i18n } = useTranslation()
  const { isCeo, isLoading: authLoading } = useAuth()
  const [jobs, setJobs] = useState([])
  const [total, setTotal] = useState(0)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState('')
  const [autoRefresh, setAutoRefresh] = useState(true)
  const [statusFilter, setStatusFilter] = useState('all')
  const [search, setSearch] = useState('')
  const [selectedJob, setSelectedJob] = useState(null)
  const [diagError, setDiagError] = useState('')
  const [lastUpdated, setLastUpdated] = useState(null)
  const hasLoadedRef = useRef(false)

  const loadJobs = useCallback(async () => {
    try {
      const qs = new URLSearchParams({ limit: '100' })

      let data
      try {
        data = await apiFetch(`/api/jobs?${qs.toString()}`)
      } catch (primaryErr) {
        if (!isCeo) throw primaryErr
        data = await apiFetch('/api/ceo/jobs/live')
      }

      const jobsList = Array.isArray(data) ? data : (data.jobs || data.items || [])
      setJobs(jobsList)
      setTotal(data.total ?? jobsList.length)
      setError('')
      setLastUpdated(new Date())
      hasLoadedRef.current = true
    } catch (err) {
      if (hasLoadedRef.current) return
      if (err?.response) {
        const text = await err.response.text().catch(() => 'Failed to load jobs')
        setError(t('pages.jobsDashboard.load_failed', { detail: text }))
      } else {
        setError(t('pages.jobsDashboard.load_error', { detail: err.message }))
      }
    } finally {
      setLoading(false)
    }
  }, [isCeo, t])

  useEffect(() => {
    if (authLoading) return
    setLoading(true)
    loadJobs()
  }, [authLoading, loadJobs])

  useVisiblePolling(loadJobs, 5000, { paused: !autoRefresh || authLoading })

  const selectedJobId = selectedJob ? selectedJob.id || selectedJob.job_id : null

  useEffect(() => {
    if (!selectedJobId) return
    const fresh = jobs.find((j) => (j.id || j.job_id) === selectedJobId)
    if (fresh) setSelectedJob(fresh)
  }, [jobs, selectedJobId])

  useEffect(() => {
    if (!selectedJobId) {
      setDiagError('')
      return undefined
    }
    let cancelled = false
    async function loadDiag() {
      try {
        const d = await apiFetch(`/api/jobs/${encodeURIComponent(selectedJobId)}/diagnostics`)
        if (cancelled || !d) return
        setDiagError('')
        setSelectedJob((prev) => {
          if (!prev || (prev.id || prev.job_id) !== selectedJobId) return prev
          return mergeJobDiagnostics(prev, d)
        })
      } catch (err) {
        if (cancelled) return
        setDiagError(err?.message || t('pages.jobsDashboard.diag_unavailable'))
      }
    }
    loadDiag()
    return () => { cancelled = true }
  }, [selectedJobId, lastUpdated, t])

  const filteredJobs = useMemo(() => {
    const q = search.trim().toLowerCase()
    return jobs.filter((j) => {
      if (!matchesOperatorFilter(j, statusFilter)) return false
      if (!q) return true
      return diagnosticsHaystack(j).includes(q)
    })
  }, [jobs, search, statusFilter])

  const statusCounts = useMemo(() => operatorStateCounts(jobs), [jobs])

  const listFindings = useMemo(() => filteredJobs.map((j) => ({
    id: j.id || j.job_id,
    severity: operatorState(j) === 'error' || operatorState(j) === 'stuck' ? 'high'
      : operatorState(j) === 'running' ? 'medium' : 'info',
    title: j.target || j.engine || String(j.id || j.job_id),
    type: j.kind || j.type || 'job',
    description: j.stuck_reason || j.last_error || '',
    resource: String(j.client_id ?? ''),
  })), [filteredJobs])

  const { filteredFindings } = useFindingsWorkbench(listFindings, {
    csvPrefix: 'weissman-jobs',
    haystackFn: (f) => `${f.title} ${f.type} ${f.description} ${f.resource}`,
  })

  function formatDuration(startTime, endTime) {
    if (!startTime) return '—'
    const start = new Date(startTime)
    const end = endTime ? new Date(endTime) : new Date()
    const diffMs = end - start
    const diffSec = Math.floor(diffMs / 1000)
    if (diffSec < 60) return `${diffSec}s`
    const diffMin = Math.floor(diffSec / 60)
    if (diffMin < 60) return `${diffMin}m ${diffSec % 60}s`
    const diffHour = Math.floor(diffMin / 60)
    return `${diffHour}h ${diffMin % 60}m`
  }

  function fmtTime(iso) {
    if (!iso) return '—'
    try {
      return new Date(iso).toLocaleString(i18n.language)
    } catch {
      return String(iso)
    }
  }

  const columns = useMemo(
    () => [
      columnHelper.accessor((j) => j.id || j.job_id, {
        id: 'job_id',
        header: t('pages.jobsDashboard.col_job_id'),
        cell: (ctx) => {
          const jobId = ctx.getValue()
          return (
            <div className="flex items-center gap-1.5">
              <code className="text-sm text-purple-400 font-mono">
                {String(jobId).slice(0, 8)}…
              </code>
              <CopyButton value={String(jobId)} label={t('pages.jobsDashboard.copy_id')} />
            </div>
          )
        },
      }),
      columnHelper.accessor((j) => j.kind || j.type || '—', {
        id: 'kind',
        header: t('pages.jobsDashboard.col_kind'),
        cell: (ctx) => (
          <span className="text-sm text-white font-medium">{ctx.getValue()}</span>
        ),
      }),
      columnHelper.accessor((j) => j.target || '', {
        id: 'target',
        header: t('pages.jobsDashboard.col_target'),
        cell: (ctx) => (
          <span
            className="text-sm text-[var(--text-secondary)] max-w-[180px] truncate block"
            title={ctx.getValue()}
          >
            {ctx.getValue() || '—'}
          </span>
        ),
      }),
      columnHelper.accessor((j) => operatorState(j), {
        id: 'status',
        header: t('pages.jobsDashboard.col_status'),
        cell: (ctx) => {
          const job = ctx.row.original
          const state = ctx.getValue()
          return (
            <div className="space-y-0.5">
              <span className={`px-2 py-1 text-xs border rounded ${operatorBadgeClass(state)}`}>
                {t(`pages.jobsDashboard.status_${state}`, { defaultValue: state })}
              </span>
              {job.stuck_reason ? (
                <div className="text-[10px] text-orange-400 max-w-[220px] truncate" title={job.stuck_reason}>
                  {job.stuck_reason}
                </div>
              ) : null}
            </div>
          )
        },
      }),
      columnHelper.accessor((j) => leaseOwner(j) || '', {
        id: 'lease',
        header: t('pages.jobsDashboard.col_lease'),
        cell: (ctx) => (
          <span className="text-[11px] font-mono text-[var(--text-secondary)] truncate block max-w-[140px]" title={ctx.getValue()}>
            {ctx.getValue() || '—'}
          </span>
        ),
      }),
      columnHelper.accessor((j) => j.created_at || '', {
        id: 'created',
        header: t('pages.jobsDashboard.col_created'),
        cell: (ctx) => (
          <span className="text-sm text-[var(--text-secondary)] whitespace-nowrap">{fmtTime(ctx.getValue())}</span>
        ),
      }),
      columnHelper.display({
        id: 'duration',
        header: t('pages.jobsDashboard.col_duration'),
        enableSorting: false,
        cell: (ctx) => (
          <span className="text-sm text-[var(--text-secondary)] whitespace-nowrap">
            {formatDuration(ctx.row.original.created_at, ctx.row.original.completed_at || ctx.row.original.updated_at)}
          </span>
        ),
      }),
    ],
    // eslint-disable-next-line react-hooks/exhaustive-deps
    [t, i18n.language],
  )

  const stuckCount = statusCounts.stuck
  const agentCount = statusCounts.blocked_by_agent
  const roeCount = statusCounts.roe_blocked

  return (
    <PageShell
      title={t('pages.jobsDashboard.title')}
      subtitle={t('pages.jobsDashboard.subtitle')}
      icon={<Briefcase className="w-5 h-5" />}
      actions={
        <>
          <label className="flex items-center gap-2 text-[11px] font-mono text-[var(--text-tertiary)]">
            <input
              type="checkbox"
              checked={autoRefresh}
              onChange={(e) => setAutoRefresh(e.target.checked)}
              className="w-3.5 h-3.5 rounded border-[var(--border-strong)] bg-[var(--bg-2)] text-cyan-500 focus:ring-cyan-500/40"
            />
            {t('pages.jobsDashboard.auto_refresh')}
          </label>
          <ShellScanActions
            onRefresh={() => { setLoading(true); loadJobs() }}
            onExport={() => exportJobsCsv(filteredJobs)}
            refreshLoading={loading}
            exportDisabled={!filteredFindings.length}
          />
        </>
      }
    >
      <div className="space-y-6">
        <div className="rounded-xl border border-cyan-500/20 bg-cyan-500/5 px-4 py-3 text-[11px] font-mono text-cyan-200/80 leading-relaxed">
          {t('pages.jobsDashboard.evidence_notice')}
        </div>

        {lastUpdated && (
          <p className="text-[11px] font-mono text-[var(--text-muted)]">
            {t('pages.jobsDashboard.last_updated', {
              time: lastUpdated.toLocaleTimeString(i18n.language),
            })}
            {' · '}
            {total === 1
              ? t('pages.jobsDashboard.jobs_tracked', { count: total })
              : t('pages.jobsDashboard.jobs_tracked_plural', { count: total })}
          </p>
        )}

        {error && (
          <div role="alert" className="p-4 bg-red-900/20 border border-red-500/30 rounded-lg text-red-400 text-sm">
            {error}
          </div>
        )}

        {stuckCount > 0 && (
          <div role="status" className="flex items-start gap-3 rounded-xl border border-orange-500/40 bg-orange-950/30 px-4 py-3">
            <AlertTriangle className="w-4 h-4 text-orange-400 mt-0.5 shrink-0 animate-pulse" />
            <p className="text-[12px] text-orange-200">
              {t('pages.jobsDashboard.stuck_banner', { count: stuckCount })}
            </p>
          </div>
        )}
        {agentCount > 0 && (
          <div role="status" className="flex items-start gap-3 rounded-xl border border-amber-500/35 bg-amber-950/25 px-4 py-3">
            <Bot className="w-4 h-4 text-amber-300 mt-0.5 shrink-0" />
            <p className="text-[12px] text-amber-100">
              {t('pages.jobsDashboard.agent_banner', { count: agentCount })}
            </p>
          </div>
        )}
        {roeCount > 0 && (
          <div role="status" className="flex items-start gap-3 rounded-xl border border-fuchsia-500/35 bg-fuchsia-950/25 px-4 py-3">
            <ShieldAlert className="w-4 h-4 text-fuchsia-300 mt-0.5 shrink-0" />
            <p className="text-[12px] text-fuchsia-100">
              {t('pages.jobsDashboard.roe_banner', { count: roeCount })}
            </p>
          </div>
        )}

        {loading && !hasLoadedRef.current ? (
          <>
            <SkeletonWidgetGrid count={8} />
            <SkeletonTable rows={8} cols={7} />
          </>
        ) : (
          <>
            <div className="grid grid-cols-2 sm:grid-cols-4 xl:grid-cols-8 gap-3">
              {TILE_STATES.map((status) => (
                <Button variant="unstyled"
                  key={status}
                  type="button"
                  onClick={() => setStatusFilter(statusFilter === status ? 'all' : status)}
                  className={`p-4 rounded-xl border text-center transition-all ${
                    statusFilter === status
                      ? 'border-cyan-500/40 bg-cyan-500/10 ring-1 ring-cyan-500/20'
                      : 'border-[var(--border-default)] bg-[var(--table-surface)] hover:border-[var(--border-strong)]'
                  }`}
                >
                  <div className={`text-2xl font-bold ${operatorBadgeClass(status === 'failed' ? 'error' : status).split(' ')[0]}`}>
                    {statusCounts[status] ?? 0}
                  </div>
                  <div className="text-[11px] text-[var(--text-tertiary)] mt-1">
                    {t(`pages.jobsDashboard.status_${status}`, { defaultValue: status })}
                  </div>
                </Button>
              ))}
            </div>

            <div className="flex flex-wrap items-center gap-3">
              <div className="relative flex-1 min-w-[200px] max-w-md">
                <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-[var(--text-disabled)] pointer-events-none" />
                <input
                  type="search"
                  value={search}
                  onChange={(e) => setSearch(e.target.value)}
                  aria-label={t('pages.jobsDashboard.search_placeholder')}
                  placeholder={t('pages.jobsDashboard.search_placeholder')}
                  className="w-full bg-[var(--bg-3)] border border-[var(--border-default)] rounded-xl pl-10 pr-3 py-2 text-sm text-[var(--text-primary)] placeholder-[var(--text-muted)] focus:outline-none focus:border-cyan-500/40"
                />
              </div>
              <div className="flex flex-wrap gap-1.5">
                {FILTER_KEYS.map((key) => (
                  <Button variant="unstyled"
                    key={key}
                    type="button"
                    onClick={() => setStatusFilter(key)}
                    className={`px-3 py-1.5 rounded-full text-[11px] font-mono border transition-all ${
                      statusFilter === key
                        ? 'bg-cyan-500/20 text-cyan-200 border-cyan-500/40'
                        : 'bg-[var(--row-hover-bg)] text-[var(--text-tertiary)] border-[var(--border-default)] hover:border-[var(--border-strong)]'
                    }`}
                  >
                    {t(`pages.jobsDashboard.filter_${key}`)}
                  </Button>
                ))}
              </div>
            </div>

            {!error && filteredJobs.length === 0 && (
              <EmptyState
                icon="⚙️"
                title={t('pages.jobsDashboard.empty_title')}
                body={search || statusFilter !== 'all'
                  ? t('pages.jobsDashboard.empty_filtered')
                  : t('pages.jobsDashboard.empty_body')}
                action={!search && statusFilter === 'all' ? (
                  <Link
                    to="/clients"
                    className="inline-block px-4 py-2 bg-purple-600 text-white rounded-lg hover:bg-purple-700 font-medium transition-colors text-sm"
                  >
                    {t('pages.jobsDashboard.go_to_clients')}
                  </Link>
                ) : null}
              />
            )}

            {filteredJobs.length > 0 && (
              <div className="grid grid-cols-1 xl:grid-cols-[1fr_360px] gap-6">
                <DataTable
                  id="jobsdash-table"
                  columns={columns}
                  data={filteredJobs}
                  onRowClick={(row) => setSelectedJob(row.original)}
                  getRowId={(j) => j.id || j.job_id}
                  selectedRowId={selectedJobId}
                  animateRows={false}
                  emptyFilteredMessage={t('pages.jobsDashboard.empty_filtered')}
                />

                <aside className="rounded-xl border border-[var(--border-default)] bg-[var(--bg-2)] p-5 space-y-4 h-fit sticky top-4">
                  <h3 className="text-sm font-semibold text-white">
                    {selectedJob ? t('pages.jobsDashboard.detail_title') : t('pages.jobsDashboard.detail_empty')}
                  </h3>
                  {selectedJob ? (
                    <JobDetailPanel
                      job={selectedJob}
                      diagError={diagError}
                      t={t}
                      fmtTime={fmtTime}
                    />
                  ) : (
                    <p className="text-[12px] text-[var(--text-muted)]">{t('pages.jobsDashboard.detail_hint')}</p>
                  )}
                </aside>
              </div>
            )}
          </>
        )}
      </div>
    </PageShell>
  )
}

function JobDetailPanel({ job, diagError, t, fmtTime }) {
  const state = operatorState(job)
  const remap = remapLabel(job)
  const owner = leaseOwner(job)
  return (
    <>
      <CopyableField
        label={t('pages.jobsDashboard.col_job_id')}
        value={job.id || job.job_id}
      />
      <div className="grid grid-cols-2 gap-3 text-[12px]">
        <div>
          <div className="text-[10px] font-mono text-[var(--text-muted)] uppercase">{t('pages.jobsDashboard.col_kind')}</div>
          <div className="text-[var(--text-secondary)] mt-0.5">{job.kind || job.type || '—'}</div>
        </div>
        <div>
          <div className="text-[10px] font-mono text-[var(--text-muted)] uppercase">{t('pages.jobsDashboard.col_operator_state')}</div>
          <span className={`inline-block mt-0.5 px-2 py-0.5 text-xs border rounded ${operatorBadgeClass(state)}`}>
            {t(`pages.jobsDashboard.status_${state}`, { defaultValue: state })}
          </span>
        </div>
        <div>
          <div className="text-[10px] font-mono text-[var(--text-muted)] uppercase">{t('pages.jobsDashboard.col_attempt')}</div>
          <div className="text-[var(--text-secondary)] mt-0.5">{job.attempt_count ?? job.retries ?? 0}</div>
        </div>
        <div>
          <div className="text-[10px] font-mono text-[var(--text-muted)] uppercase">{t('pages.jobsDashboard.field_client')}</div>
          <div className="text-[var(--text-secondary)] mt-0.5">
            {job.client_id != null ? (
              <Link to={`/clients/${job.client_id}`} className="text-cyan-400 hover:underline">
                #{job.client_id}
              </Link>
            ) : '—'}
          </div>
        </div>
      </div>
      {job.target && (
        <CopyableField label={t('pages.jobsDashboard.col_target')} value={job.target} />
      )}
      {job.engine && (
        <CopyableField label={t('pages.jobsDashboard.field_engine')} value={job.engine} />
      )}
      {remap?.wasRemapped && (
        <div className="rounded-lg border border-cyan-500/25 bg-cyan-950/20 p-3">
          <div className="text-[10px] font-mono text-cyan-300/70 uppercase mb-1">
            {t('pages.jobsDashboard.field_remap')}
          </div>
          <div className="text-[12px] text-cyan-100 font-mono">
            {remap.requested} → {remap.canonical}
          </div>
        </div>
      )}

      <div className="rounded-lg border border-[var(--border-default)] bg-[var(--bg-3)] p-3 space-y-2">
        <div className="text-[10px] font-mono text-[var(--text-muted)] uppercase">
          {t('pages.jobsDashboard.diag_title')}
        </div>
        {diagError && (
          <div role="alert" className="text-[11px] text-rose-300">{diagError}</div>
        )}
        <div className="text-[11px] font-mono text-[var(--text-secondary)] space-y-1">
          <div>{t('pages.jobsDashboard.field_lease_owner')}: {owner || t('pages.jobsDashboard.field_lease_missing')}</div>
          <div>
            {t('pages.jobsDashboard.field_lease_ttl')}:{' '}
            {job.lease_present === false
              ? t('pages.jobsDashboard.field_lease_missing')
              : job.lease_ttl_secs != null
                ? `${job.lease_ttl_secs}s`
                : job.lease_inspect_ok === false
                  ? t('pages.jobsDashboard.diag_unavailable')
                  : '—'}
          </div>
          <div>
            {t('pages.jobsDashboard.field_heartbeat')}: {fmtTime(job.heartbeat_at)}
            {job.heartbeat_stale_secs != null ? ` (${job.heartbeat_stale_secs}s)` : ''}
          </div>
          {job.locked_until && (
            <div>{t('pages.jobsDashboard.field_locked_until')}: {fmtTime(job.locked_until)}</div>
          )}
          {job.run_after && (
            <div>{t('pages.jobsDashboard.field_run_after')}: {fmtTime(job.run_after)}</div>
          )}
          {job.swarm_worker_alive != null && (
            <div>
              {t('pages.jobsDashboard.field_swarm')}:{' '}
              {job.swarm_worker_alive
                ? t('pages.jobsDashboard.swarm_alive')
                : t('pages.jobsDashboard.swarm_dead')}
            </div>
          )}
          {job.live_phase && (
            <div>{t('pages.jobsDashboard.field_phase')}: {job.live_phase}
              {job.live_phase_idle_secs != null ? ` (${job.live_phase_idle_secs}s)` : ''}
            </div>
          )}
        </div>
      </div>

      {job.stuck_reason && (
        <div role="status" className="rounded-lg border border-orange-500/30 bg-orange-950/20 p-3">
          <div className="text-[10px] font-mono text-orange-300/70 uppercase mb-1">
            {t('pages.jobsDashboard.field_stuck_reason')}
          </div>
          <pre className="text-[11px] font-mono text-orange-100 whitespace-pre-wrap break-words">
            {job.stuck_reason}
          </pre>
        </div>
      )}

      {owner && (
        <CopyableField label={t('pages.jobsDashboard.field_worker')} value={owner} />
      )}
      <div className="text-[11px] font-mono text-[var(--text-muted)] space-y-1">
        <div>{t('pages.jobsDashboard.field_created')}: {fmtTime(job.created_at)}</div>
        <div>{t('pages.jobsDashboard.field_updated')}: {fmtTime(job.updated_at)}</div>
      </div>
      {job.last_error && (
        <div role="alert" className="rounded-lg border border-rose-500/30 bg-rose-950/20 p-3">
          <div className="text-[10px] font-mono text-rose-300/70 uppercase mb-1">
            {t('pages.jobsDashboard.field_error')}
          </div>
          <pre className="text-[11px] font-mono text-rose-200 whitespace-pre-wrap break-words">
            {job.last_error}
          </pre>
        </div>
      )}
    </>
  )
}
