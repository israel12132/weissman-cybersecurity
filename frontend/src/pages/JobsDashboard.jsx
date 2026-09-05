import { useEffect, useState, useCallback, useRef, useMemo } from 'react'
import { Link } from 'react-router'
import { useTranslation } from 'react-i18next'
import { Search, Briefcase } from 'lucide-react'
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
  JOBS_CSV_HEADER,
  diagnosticsHaystack,
  jobToCsvRow,
  leaseOwner,
  matchesOperatorFilter,
  operatorBadgeClass,
  operatorState,
  operatorStateCounts,
  overlayStuckReasons,
  parseDiagnosticsCensus,
  remapLabel,
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

function jobSeverity(job) {
  const s = operatorState(job)
  if (s === 'failed' || s === 'error' || s === 'stuck' || s === 'roe_blocked') return 'high'
  if (s === 'running' || s === 'blocked_by_agent') return 'medium'
  return 'info'
}

export default function JobsDashboard() {
  const { t, i18n } = useTranslation()
  const { isCeo, isLoading: authLoading } = useAuth()
  const [jobs, setJobs] = useState([])
  const [total, setTotal] = useState(0)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState('')
  const [census, setCensus] = useState(null)
  const [censusError, setCensusError] = useState('')
  const [autoRefresh, setAutoRefresh] = useState(true)
  const [statusFilter, setStatusFilter] = useState('all')
  const [search, setSearch] = useState('')
  const [selectedJob, setSelectedJob] = useState(null)
  const [lastUpdated, setLastUpdated] = useState(null)
  const hasLoadedRef = useRef(false)

  const loadJobs = useCallback(async () => {
    try {
      const qs = new URLSearchParams({ limit: '100' })
      const jobsPromise = (async () => {
        try {
          return await apiFetch(`/api/jobs?${qs.toString()}`)
        } catch (primaryErr) {
          if (!isCeo) throw primaryErr
          return await apiFetch('/api/ceo/jobs/live')
        }
      })()
      const diagPromise = apiFetch('/api/jobs/diagnostics').then(
        (body) => ({ ok: true, body }),
        (err) => ({ ok: false, err }),
      )

      const [data, diagRes] = await Promise.all([jobsPromise, diagPromise])
      let jobsList = Array.isArray(data) ? data : (data.jobs || data.items || [])

      if (diagRes.ok) {
        const parsed = parseDiagnosticsCensus(diagRes.body)
        setCensus(parsed)
        if (parsed.ok) {
          setCensusError('')
          jobsList = overlayStuckReasons(jobsList, parsed.stuck)
        } else {
          setCensusError(
            t('pages.jobsDashboard.census_incomplete', {
              field: parsed.field || 'payload',
            }),
          )
        }
      } else {
        setCensus(null)
        const detail = diagRes.err?.message || String(diagRes.err || 'diagnostics unavailable')
        setCensusError(t('pages.jobsDashboard.census_unavailable', { detail }))
      }

      setJobs(jobsList)
      setTotal(data.total ?? jobsList.length)
      setSelectedJob((current) => {
        if (!current) return current
        const id = current.id || current.job_id
        return jobsList.find((j) => (j.id || j.job_id) === id) || current
      })
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

  const filteredJobs = useMemo(() => {
    const q = search.trim().toLowerCase()
    return jobs.filter((j) => {
      if (!matchesOperatorFilter(j, statusFilter)) return false
      if (!q) return true
      return diagnosticsHaystack(j).includes(q)
    })
  }, [jobs, search, statusFilter])

  const statusCounts = useMemo(() => operatorStateCounts(jobs), [jobs])

  const listFindings = useMemo(
    () =>
      filteredJobs.map((j) => ({
        id: j.id || j.job_id,
        severity: jobSeverity(j),
        title: j.target || j.engine || String(j.id || j.job_id),
        type: j.kind || j.type || 'job',
        description: j.stuck_reason || j.last_error || '',
        resource: String(j.client_id ?? ''),
      })),
    [filteredJobs],
  )

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

  const statusLabel = (state) =>
    t(`pages.jobsDashboard.status_${state}`, { defaultValue: state })

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
        cell: (ctx) => (
          <span className={`px-2 py-1 text-xs border rounded ${operatorBadgeClass(ctx.getValue())}`}>
            {statusLabel(ctx.getValue())}
          </span>
        ),
      }),
      columnHelper.accessor((j) => j.stuck_reason || '', {
        id: 'stuck_reason',
        header: t('pages.jobsDashboard.field_stuck_reason'),
        cell: (ctx) => (
          <span
            className="text-[11px] text-orange-300/90 max-w-[220px] truncate block"
            title={ctx.getValue()}
          >
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

  const selectedJobId = selectedJob ? selectedJob.id || selectedJob.job_id : null
  const selectedRemap = remapLabel(selectedJob)
  const selectedLease = leaseOwner(selectedJob)
  const redisLabel = !census?.ok
    ? '—'
    : !census.redisConfigured
      ? t('pages.jobsDashboard.census_redis_unconfigured')
      : census.redisInspectOk
        ? t('pages.jobsDashboard.census_redis_ok')
        : t('pages.jobsDashboard.census_redis_down')

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

        <div
          data-testid="jobs-census"
          className="rounded-xl border border-[var(--border-default)] bg-[var(--table-surface)] px-4 py-3"
        >
          <div className="text-[10px] font-mono uppercase tracking-wider text-[var(--text-muted)] mb-2">
            {t('pages.jobsDashboard.census_title')}
          </div>
          {censusError ? (
            <p role="alert" className="text-sm text-orange-300 mb-2">
              {censusError}
            </p>
          ) : null}
          <div className="grid grid-cols-2 md:grid-cols-4 gap-3 text-sm">
              <div>
                <div className="text-[10px] font-mono text-[var(--text-muted)] uppercase">
                  {t('pages.jobsDashboard.census_redis')}
                </div>
                <div className="mt-0.5 text-white" data-testid="jobs-census-redis">{redisLabel}</div>
              </div>
              <div>
                <div className="text-[10px] font-mono text-[var(--text-muted)] uppercase">
                  {t('pages.jobsDashboard.census_workers')}
                </div>
                <div className="mt-0.5 text-white" data-testid="jobs-census-workers">
                  {census?.ok ? `${census.workersAlive}/${census.workersInspected}` : '—'}
                </div>
              </div>
              <div>
                <div className="text-[10px] font-mono text-[var(--text-muted)] uppercase">
                  {t('pages.jobsDashboard.census_pending_unsigned')}
                </div>
                <div className="mt-0.5 text-white" data-testid="jobs-census-pending">
                  {census?.ok ? census.pendingNoEnvelope : '—'}
                </div>
              </div>
              <div>
                <div className="text-[10px] font-mono text-[var(--text-muted)] uppercase">
                  {t('pages.jobsDashboard.census_stuck')}
                </div>
                <div className="mt-0.5 text-white" data-testid="jobs-census-stuck">
                  {census?.ok ? census.stuck.length : '—'}
                </div>
              </div>
            </div>
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
          <div className="p-4 bg-red-900/20 border border-red-500/30 rounded-lg text-red-400 text-sm">
            {error}
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
                  data-testid={`jobs-tile-${status}`}
                  onClick={() => setStatusFilter(statusFilter === status ? 'all' : status)}
                  className={`p-4 rounded-xl border text-center transition-all ${
                    statusFilter === status
                      ? 'border-cyan-500/40 bg-cyan-500/10 ring-1 ring-cyan-500/20'
                      : 'border-[var(--border-default)] bg-[var(--table-surface)] hover:border-[var(--border-strong)]'
                  }`}
                >
                  <div className={`text-2xl font-bold ${operatorBadgeClass(status).split(' ')[0]}`}>
                    {statusCounts[status] ?? 0}
                  </div>
                  <div className="text-[11px] text-[var(--text-tertiary)] mt-1">
                    {statusLabel(status)}
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
                    {key === 'all'
                      ? t('pages.jobsDashboard.filter_all')
                      : t(`pages.jobsDashboard.filter_${key}`, { defaultValue: statusLabel(key) })}
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
              <div className="grid grid-cols-1 xl:grid-cols-[1fr_340px] gap-6">
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
                    <>
                      <CopyableField
                        label={t('pages.jobsDashboard.col_job_id')}
                        value={selectedJob.id || selectedJob.job_id}
                      />
                      <div className="grid grid-cols-2 gap-3 text-[12px]">
                        <div>
                          <div className="text-[10px] font-mono text-[var(--text-muted)] uppercase">{t('pages.jobsDashboard.col_kind')}</div>
                          <div className="text-[var(--text-secondary)] mt-0.5">{selectedJob.kind || selectedJob.type || '—'}</div>
                        </div>
                        <div>
                          <div className="text-[10px] font-mono text-[var(--text-muted)] uppercase">{t('pages.jobsDashboard.field_operator')}</div>
                          <span className={`inline-block mt-0.5 px-2 py-0.5 text-xs border rounded ${operatorBadgeClass(selectedJob)}`}>
                            {statusLabel(operatorState(selectedJob))}
                          </span>
                        </div>
                        <div>
                          <div className="text-[10px] font-mono text-[var(--text-muted)] uppercase">{t('pages.jobsDashboard.col_attempt')}</div>
                          <div className="text-[var(--text-secondary)] mt-0.5">{selectedJob.attempt_count ?? selectedJob.retries ?? 0}</div>
                        </div>
                        <div>
                          <div className="text-[10px] font-mono text-[var(--text-muted)] uppercase">{t('pages.jobsDashboard.field_client')}</div>
                          <div className="text-[var(--text-secondary)] mt-0.5">
                            {selectedJob.client_id != null ? (
                              <Link to={`/clients/${selectedJob.client_id}`} className="text-cyan-400 hover:underline">
                                #{selectedJob.client_id}
                              </Link>
                            ) : '—'}
                          </div>
                        </div>
                      </div>
                      {selectedJob.target && (
                        <CopyableField label={t('pages.jobsDashboard.col_target')} value={selectedJob.target} />
                      )}
                      {selectedJob.engine && (
                        <CopyableField label={t('pages.jobsDashboard.field_engine')} value={selectedJob.engine} />
                      )}
                      {selectedLease && (
                        <CopyableField label={t('pages.jobsDashboard.field_lease')} value={selectedLease} />
                      )}
                      {selectedRemap && (
                        <div className="text-[12px] text-[var(--text-secondary)]">
                          <div className="text-[10px] font-mono text-[var(--text-muted)] uppercase">
                            {t('pages.jobsDashboard.field_remap')}
                          </div>
                          <div className="mt-0.5 font-mono">
                            {selectedRemap.requested}
                            {selectedRemap.wasRemapped ? ` → ${selectedRemap.canonical}` : ''}
                          </div>
                        </div>
                      )}
                      {selectedJob.stuck_reason && (
                        <div role="status" className="rounded-lg border border-orange-500/30 bg-orange-950/20 p-3">
                          <div className="text-[10px] font-mono text-orange-300/70 uppercase mb-1">
                            {t('pages.jobsDashboard.field_stuck_reason')}
                          </div>
                          <pre className="text-[11px] font-mono text-orange-100 whitespace-pre-wrap break-words">
                            {selectedJob.stuck_reason}
                          </pre>
                        </div>
                      )}
                      <div className="text-[11px] font-mono text-[var(--text-muted)] space-y-1">
                        <div>{t('pages.jobsDashboard.field_created')}: {fmtTime(selectedJob.created_at)}</div>
                        <div>{t('pages.jobsDashboard.field_updated')}: {fmtTime(selectedJob.updated_at)}</div>
                        {selectedJob.heartbeat_at && (
                          <div>{t('pages.jobsDashboard.field_heartbeat')}: {fmtTime(selectedJob.heartbeat_at)}</div>
                        )}
                      </div>
                      {selectedJob.last_error && (
                        <div role="alert" className="rounded-lg border border-rose-500/30 bg-rose-950/20 p-3">
                          <div className="text-[10px] font-mono text-rose-300/70 uppercase mb-1">
                            {t('pages.jobsDashboard.field_error')}
                          </div>
                          <pre className="text-[11px] font-mono text-rose-200 whitespace-pre-wrap break-words">
                            {selectedJob.last_error}
                          </pre>
                        </div>
                      )}
                    </>
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
