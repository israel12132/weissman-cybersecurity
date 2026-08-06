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
import { normalizeJobStatus } from '../lib/useJobPoll'
import { useVisiblePolling } from '../hooks/useVisiblePolling'
import { useAuth } from '../context/AuthContext'
import Button from '../components/ui/Button'

const columnHelper = createColumnHelper()

const STATUS_COLORS = {
  queued: 'text-yellow-400 bg-yellow-900/20 border-yellow-500/30',
  running: 'text-blue-400 bg-blue-900/20 border-blue-500/30',
  completed: 'text-green-400 bg-green-900/20 border-green-500/30',
  failed: 'text-red-400 bg-red-900/20 border-red-500/30',
  cancelled: 'text-[var(--text-tertiary)] bg-[var(--bg-1)]/20 border-[var(--border-strong)]/30',
}

const STATUS_KEYS = ['all', 'queued', 'running', 'completed', 'failed', 'cancelled']

function exportJobsCsv(jobs, _t) {
  const header = ['id', 'kind', 'status', 'target', 'engine', 'client_id', 'created_at', 'updated_at', 'attempt_count', 'last_error']
  const esc = (v) => `"${String(v ?? '').replace(/"/g, '""')}"`
  const lines = [
    header.join(','),
    ...jobs.map((j) =>
      [
        j.id || j.job_id,
        j.kind || j.type,
        normalizeJobStatus(j.status),
        j.target,
        j.engine,
        j.client_id,
        j.created_at,
        j.updated_at || j.completed_at,
        j.attempt_count ?? j.retries,
        j.last_error,
      ].map(esc).join(','),
    ),
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
  const [lastUpdated, setLastUpdated] = useState(null)
  const hasLoadedRef = useRef(false)

  const loadJobs = useCallback(async () => {
    try {
      const qs = new URLSearchParams({ limit: '100' })
      if (statusFilter !== 'all') qs.set('status', statusFilter)

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
  }, [isCeo, statusFilter, t])

  useEffect(() => {
    if (authLoading) return
    setLoading(true)
    loadJobs()
  }, [authLoading, loadJobs])

  // Auto-refresh every 5s, skipping ticks while the tab is hidden.
  useVisiblePolling(loadJobs, 5000, { paused: !autoRefresh || authLoading })

  const filteredJobs = useMemo(() => {
    const q = search.trim().toLowerCase()
    if (!q) return jobs
    return jobs.filter((j) => {
      const hay = [
        j.id, j.job_id, j.kind, j.type, j.status, j.target, j.engine,
        j.client_id != null ? String(j.client_id) : '',
        j.last_error,
      ].filter(Boolean).join(' ').toLowerCase()
      return hay.includes(q)
    })
  }, [jobs, search])

  const statusCounts = useMemo(() => {
    const counts = { queued: 0, running: 0, completed: 0, failed: 0, cancelled: 0 }
    for (const j of jobs) {
      const s = normalizeJobStatus(j.status)
      if (counts[s] != null) counts[s] += 1
    }
    return counts
  }, [jobs])

  const listFindings = useMemo(() => filteredJobs.map((j) => ({
    id: j.id || j.job_id,
    severity: normalizeJobStatus(j.status) === 'failed' ? 'high' : normalizeJobStatus(j.status) === 'running' ? 'medium' : 'info',
    title: j.target || j.engine || String(j.id || j.job_id),
    type: j.kind || j.type || 'job',
    description: j.last_error || '',
    resource: String(j.client_id ?? ''),
  })), [filteredJobs])

  const { filteredFindings } = useFindingsWorkbench(listFindings, {
    csvPrefix: 'weissman-jobs',
    haystackFn: (f) => `${f.title} ${f.type} ${f.description} ${f.resource}`,
  })

  function getStatusBadgeClass(status) {
    const statusLower = normalizeJobStatus(status)
    return STATUS_COLORS[statusLower] || 'text-[var(--text-tertiary)] bg-[var(--bg-1)]/20 border-[var(--border-strong)]/30'
  }

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
      columnHelper.accessor((j) => normalizeJobStatus(j.status), {
        id: 'status',
        header: t('pages.jobsDashboard.col_status'),
        cell: (ctx) => (
          <span className={`px-2 py-1 text-xs border rounded ${getStatusBadgeClass(ctx.row.original.status)}`}>
            {ctx.getValue() || 'unknown'}
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
            onExport={() => exportJobsCsv(filteredJobs, t)}
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
          <div className="p-4 bg-red-900/20 border border-red-500/30 rounded-lg text-red-400 text-sm">
            {error}
          </div>
        )}

        {loading && !hasLoadedRef.current ? (
          <>
            <SkeletonWidgetGrid count={5} />
            <SkeletonTable rows={8} cols={6} />
          </>
        ) : (
          <>
            <div className="grid grid-cols-2 md:grid-cols-5 gap-3">
              {['queued', 'running', 'completed', 'failed', 'cancelled'].map((status) => (
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
                  <div className={`text-2xl font-bold ${getStatusBadgeClass(status).split(' ')[0]}`}>
                    {statusCounts[status]}
                  </div>
                  <div className="text-[11px] text-[var(--text-tertiary)] capitalize mt-1">
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
                {STATUS_KEYS.map((key) => (
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
                          <div className="text-[10px] font-mono text-[var(--text-muted)] uppercase">{t('pages.jobsDashboard.col_status')}</div>
                          <span className={`inline-block mt-0.5 px-2 py-0.5 text-xs border rounded ${getStatusBadgeClass(selectedJob.status)}`}>
                            {normalizeJobStatus(selectedJob.status)}
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
                      {selectedJob.worker_id && (
                        <CopyableField label={t('pages.jobsDashboard.field_worker')} value={selectedJob.worker_id} />
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
