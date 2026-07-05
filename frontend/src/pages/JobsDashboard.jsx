import { useEffect, useState, useCallback, useRef, useMemo } from 'react'
import { Link } from 'react-router-dom'
import { useTranslation } from 'react-i18next'
import { RefreshCw, Search, Download, Briefcase } from 'lucide-react'
import PageShell from './PageShell'
import ShellScanActions from '../components/engine/ShellScanActions'
import { useFindingsWorkbench } from '../hooks/useFindingsWorkbench'
import EmptyState from '../components/ui/EmptyState'
import { SkeletonTable, SkeletonWidgetGrid } from '../components/ui/Skeleton'
import CopyButton, { CopyableField } from '../components/ui/CopyButton'
import { apiFetch } from '../lib/apiBase'
import { normalizeJobStatus } from '../lib/useJobPoll'
import { useAuth } from '../context/AuthContext'

const STATUS_COLORS = {
  queued: 'text-yellow-400 bg-yellow-900/20 border-yellow-500/30',
  running: 'text-blue-400 bg-blue-900/20 border-blue-500/30',
  completed: 'text-green-400 bg-green-900/20 border-green-500/30',
  failed: 'text-red-400 bg-red-900/20 border-red-500/30',
  cancelled: 'text-slate-400 bg-slate-900/20 border-slate-500/30',
}

const STATUS_KEYS = ['all', 'queued', 'running', 'completed', 'failed', 'cancelled']

function exportJobsCsv(jobs, t) {
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
  const [statusCountsFromApi, setStatusCountsFromApi] = useState(null)
  const [lastUpdated, setLastUpdated] = useState(null)
  const hasLoadedRef = useRef(false)

  const loadJobs = useCallback(async () => {
    try {
      const qs = new URLSearchParams({ limit: '100' })
      if (statusFilter !== 'all') qs.set('status', statusFilter)

      let response = await apiFetch(`/api/jobs?${qs.toString()}`)

      if (!response.ok && isCeo) {
        response = await apiFetch('/api/ceo/jobs/live')
      }

      if (!response.ok) {
        if (hasLoadedRef.current) return
        const text = await response.text().catch(() => 'Failed to load jobs')
        setError(t('pages.jobsDashboard.load_failed', { detail: text }))
        setLoading(false)
        return
      }

      const data = await response.json()
      const jobsList = Array.isArray(data) ? data : (data.jobs || data.items || [])
      setJobs(jobsList)
      setTotal(data.total ?? jobsList.length)
      setStatusCountsFromApi(data.status_counts ?? null)
      setError('')
      setLastUpdated(new Date())
      hasLoadedRef.current = true
    } catch (err) {
      if (hasLoadedRef.current) return
      setError(t('pages.jobsDashboard.load_error', { detail: err.message }))
    } finally {
      setLoading(false)
    }
  }, [isCeo, statusFilter, t])

  useEffect(() => {
    if (authLoading) return
    setLoading(true)
    loadJobs()
  }, [authLoading, loadJobs])

  useEffect(() => {
    if (!autoRefresh || authLoading) return
    const interval = setInterval(loadJobs, 5000)
    return () => clearInterval(interval)
  }, [autoRefresh, authLoading, loadJobs])

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
    if (statusCountsFromApi && typeof statusCountsFromApi === 'object') {
      return {
        queued: statusCountsFromApi.queued ?? 0,
        running: statusCountsFromApi.running ?? 0,
        completed: statusCountsFromApi.completed ?? 0,
        failed: statusCountsFromApi.failed ?? 0,
        cancelled: statusCountsFromApi.cancelled ?? 0,
      }
    }
    const counts = { queued: 0, running: 0, completed: 0, failed: 0, cancelled: 0 }
    for (const j of jobs) {
      const s = normalizeJobStatus(j.status)
      if (counts[s] != null) counts[s] += 1
    }
    return counts
  }, [jobs, statusCountsFromApi])

  const listFindings = useMemo(() => filteredJobs.map((j) => ({
    id: j.id || j.job_id,
    severity: normalizeJobStatus(j.status) === 'failed' ? 'high' : normalizeJobStatus(j.status) === 'running' ? 'medium' : 'info',
    title: j.target || j.engine || String(j.id || j.job_id),
    type: j.kind || j.type || 'job',
    description: j.last_error || '',
    resource: String(j.client_id ?? ''),
  })), [filteredJobs])

  const { exportCsv: exportWorkbenchCsv, filteredFindings } = useFindingsWorkbench(listFindings, {
    csvPrefix: 'weissman-jobs',
    haystackFn: (f) => `${f.title} ${f.type} ${f.description} ${f.resource}`,
  })

  function getStatusBadgeClass(status) {
    const statusLower = normalizeJobStatus(status)
    return STATUS_COLORS[statusLower] || 'text-slate-400 bg-slate-900/20 border-slate-500/30'
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

  return (
    <PageShell
      title={t('pages.jobsDashboard.title')}
      subtitle={t('pages.jobsDashboard.subtitle')}
      icon={<Briefcase className="w-5 h-5" />}
      actions={
        <>
          <label className="flex items-center gap-2 text-[11px] font-mono text-white/55">
            <input
              type="checkbox"
              checked={autoRefresh}
              onChange={(e) => setAutoRefresh(e.target.checked)}
              className="w-3.5 h-3.5 rounded border-white/20 bg-black/40 text-cyan-500 focus:ring-cyan-500/40"
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
          <p className="text-[11px] font-mono text-white/40">
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
                <button
                  key={status}
                  type="button"
                  onClick={() => setStatusFilter(statusFilter === status ? 'all' : status)}
                  className={`p-4 rounded-xl border text-center transition-all ${
                    statusFilter === status
                      ? 'border-cyan-500/40 bg-cyan-500/10 ring-1 ring-cyan-500/20'
                      : 'border-white/10 bg-black/30 hover:border-white/20'
                  }`}
                >
                  <div className={`text-2xl font-bold ${getStatusBadgeClass(status).split(' ')[0]}`}>
                    {statusCounts[status]}
                  </div>
                  <div className="text-[11px] text-slate-400 capitalize mt-1">
                    {t(`pages.jobsDashboard.status_${status}`, { defaultValue: status })}
                  </div>
                </button>
              ))}
            </div>

            <div className="flex flex-wrap items-center gap-3">
              <div className="relative flex-1 min-w-[200px] max-w-md">
                <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-white/30 pointer-events-none" />
                <input
                  type="search"
                  value={search}
                  onChange={(e) => setSearch(e.target.value)}
                  placeholder={t('pages.jobsDashboard.search_placeholder')}
                  className="w-full bg-black/50 border border-white/10 rounded-xl pl-10 pr-3 py-2 text-sm text-white/85 placeholder-white/30 focus:outline-none focus:border-cyan-500/40"
                />
              </div>
              <div className="flex flex-wrap gap-1.5">
                {STATUS_KEYS.map((key) => (
                  <button
                    key={key}
                    type="button"
                    onClick={() => setStatusFilter(key)}
                    className={`px-3 py-1.5 rounded-full text-[11px] font-mono border transition-all ${
                      statusFilter === key
                        ? 'bg-cyan-500/20 text-cyan-200 border-cyan-500/40'
                        : 'bg-white/5 text-white/50 border-white/10 hover:border-white/25'
                    }`}
                  >
                    {t(`pages.jobsDashboard.filter_${key}`)}
                  </button>
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
                <div className="bg-slate-800/50 border border-slate-700 rounded-xl overflow-hidden">
                  <div className="overflow-x-auto">
                    <table className="w-full">
                      <thead>
                        <tr className="border-b border-slate-700">
                          {['col_job_id', 'col_kind', 'col_target', 'col_status', 'col_created', 'col_duration'].map((col) => (
                            <th key={col} className="px-4 py-3 text-left text-xs font-medium text-slate-400 uppercase tracking-wider">
                              {t(`pages.jobsDashboard.${col}`)}
                            </th>
                          ))}
                        </tr>
                      </thead>
                      <tbody className="divide-y divide-slate-700">
                        {filteredJobs.map((job) => {
                          const jobId = job.id || job.job_id
                          const selected = selectedJob && (selectedJob.id || selectedJob.job_id) === jobId
                          return (
                            <tr
                              key={jobId}
                              onClick={() => setSelectedJob(job)}
                              className={`cursor-pointer transition-colors ${
                                selected ? 'bg-cyan-950/30' : 'hover:bg-slate-800/30'
                              }`}
                            >
                              <td className="px-4 py-3 whitespace-nowrap">
                                <div className="flex items-center gap-1.5">
                                  <code className="text-sm text-purple-400 font-mono">
                                    {String(jobId).slice(0, 8)}…
                                  </code>
                                  <CopyButton value={String(jobId)} label={t('pages.jobsDashboard.copy_id')} />
                                </div>
                              </td>
                              <td className="px-4 py-3 whitespace-nowrap text-sm text-white font-medium">
                                {job.kind || job.type || '—'}
                              </td>
                              <td className="px-4 py-3 text-sm text-slate-300 max-w-[180px] truncate" title={job.target}>
                                {job.target || '—'}
                              </td>
                              <td className="px-4 py-3 whitespace-nowrap">
                                <span className={`px-2 py-1 text-xs border rounded ${getStatusBadgeClass(job.status)}`}>
                                  {normalizeJobStatus(job.status) || 'unknown'}
                                </span>
                              </td>
                              <td className="px-4 py-3 whitespace-nowrap text-sm text-slate-300">
                                {fmtTime(job.created_at)}
                              </td>
                              <td className="px-4 py-3 whitespace-nowrap text-sm text-slate-300">
                                {formatDuration(job.created_at, job.completed_at || job.updated_at)}
                              </td>
                            </tr>
                          )
                        })}
                      </tbody>
                    </table>
                  </div>
                </div>

                <aside className="rounded-xl border border-white/10 bg-black/40 p-5 space-y-4 h-fit sticky top-4">
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
                          <div className="text-[10px] font-mono text-white/40 uppercase">{t('pages.jobsDashboard.col_kind')}</div>
                          <div className="text-white/80 mt-0.5">{selectedJob.kind || selectedJob.type || '—'}</div>
                        </div>
                        <div>
                          <div className="text-[10px] font-mono text-white/40 uppercase">{t('pages.jobsDashboard.col_status')}</div>
                          <span className={`inline-block mt-0.5 px-2 py-0.5 text-xs border rounded ${getStatusBadgeClass(selectedJob.status)}`}>
                            {normalizeJobStatus(selectedJob.status)}
                          </span>
                        </div>
                        <div>
                          <div className="text-[10px] font-mono text-white/40 uppercase">{t('pages.jobsDashboard.col_attempt')}</div>
                          <div className="text-white/80 mt-0.5">{selectedJob.attempt_count ?? selectedJob.retries ?? 0}</div>
                        </div>
                        <div>
                          <div className="text-[10px] font-mono text-white/40 uppercase">{t('pages.jobsDashboard.field_client')}</div>
                          <div className="text-white/80 mt-0.5">
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
                      <div className="text-[11px] font-mono text-white/45 space-y-1">
                        <div>{t('pages.jobsDashboard.field_created')}: {fmtTime(selectedJob.created_at)}</div>
                        <div>{t('pages.jobsDashboard.field_updated')}: {fmtTime(selectedJob.updated_at)}</div>
                        {selectedJob.heartbeat_at && (
                          <div>{t('pages.jobsDashboard.field_heartbeat')}: {fmtTime(selectedJob.heartbeat_at)}</div>
                        )}
                      </div>
                      {selectedJob.last_error && (
                        <div className="rounded-lg border border-rose-500/30 bg-rose-950/20 p-3">
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
                    <p className="text-[12px] text-white/45">{t('pages.jobsDashboard.detail_hint')}</p>
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
