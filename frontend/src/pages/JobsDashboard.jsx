import { useEffect, useState } from 'react'
import { Link } from 'react-router-dom'
import PageShell from './PageShell'
import { apiFetch } from '../lib/apiBase'

const STATUS_COLORS = {
  queued: 'text-yellow-400 bg-yellow-900/20 border-yellow-500/30',
  running: 'text-blue-400 bg-blue-900/20 border-blue-500/30',
  completed: 'text-green-400 bg-green-900/20 border-green-500/30',
  failed: 'text-red-400 bg-red-900/20 border-red-500/30',
  cancelled: 'text-slate-400 bg-slate-900/20 border-slate-500/30',
}

export default function JobsDashboard() {
  const [jobs, setJobs] = useState([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState('')
  const [autoRefresh, setAutoRefresh] = useState(true)

  useEffect(() => {
    loadJobs()
  }, [])

  useEffect(() => {
    if (!autoRefresh) return
    const interval = setInterval(() => {
      loadJobs()
    }, 5000) // Refresh every 5 seconds
    return () => clearInterval(interval)
  }, [autoRefresh])

  async function loadJobs() {
    try {
      // Note: This endpoint may need to be implemented in the backend
      // For now, we'll try different possible endpoints
      let response = await apiFetch('/api/jobs?limit=50')

      if (!response.ok) {
        // Try alternative endpoint
        response = await apiFetch('/api/ceo/jobs/live')
      }

      if (!response.ok) {
        if (!loading) return // Don't show error on refresh if already loaded
        const text = await response.text().catch(() => 'Failed to load jobs')
        setError(`Failed to load jobs: ${text}`)
        setLoading(false)
        return
      }

      const data = await response.json()
      // Handle different response formats
      const jobsList = Array.isArray(data) ? data : (data.jobs || data.items || [])
      setJobs(jobsList)
      setError('')
    } catch (err) {
      if (!loading) return // Don't show error on refresh
      setError(`Error loading jobs: ${err.message}`)
    } finally {
      setLoading(false)
    }
  }

  function getStatusBadgeClass(status) {
    const statusLower = (status || '').toLowerCase()
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

  return (
    <PageShell title="Jobs Dashboard" subtitle="Monitor scan jobs and background tasks">
      <div className="space-y-6">
        {/* Header */}
        <div className="flex items-center justify-between">
          <div>
            <h2 className="text-2xl font-bold text-white">Active & Recent Jobs</h2>
            <p className="text-sm text-slate-400 mt-1">
              {jobs.length} job{jobs.length !== 1 ? 's' : ''} tracked
            </p>
          </div>
          <div className="flex items-center gap-4">
            <label className="flex items-center gap-2 text-sm text-slate-300">
              <input
                type="checkbox"
                checked={autoRefresh}
                onChange={(e) => setAutoRefresh(e.target.checked)}
                className="w-4 h-4 text-purple-600 bg-slate-900 border-slate-600 rounded focus:ring-purple-500"
              />
              Auto-refresh (5s)
            </label>
            <button
              onClick={() => loadJobs()}
              className="px-4 py-2 bg-slate-700 text-white rounded-lg hover:bg-slate-600 transition-colors"
            >
              ↻ Refresh Now
            </button>
          </div>
        </div>

        {/* Error State */}
        {error && (
          <div className="p-4 bg-red-900/20 border border-red-500/30 rounded-lg text-red-400">
            {error}
          </div>
        )}

        {/* Loading State */}
        {loading && (
          <div className="text-center py-12 text-slate-400">
            <div className="inline-block w-8 h-8 border-4 border-purple-500 border-t-transparent rounded-full animate-spin" />
            <p className="mt-4">Loading jobs...</p>
          </div>
        )}

        {/* Empty State */}
        {!loading && !error && jobs.length === 0 && (
          <div className="text-center py-12 border-2 border-dashed border-slate-700 rounded-lg">
            <svg className="mx-auto h-12 w-12 text-slate-600" fill="none" stroke="currentColor" viewBox="0 0 48 48">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 8v28m8-28v28m8-28v28m8-28v28" />
            </svg>
            <h3 className="mt-4 text-lg font-medium text-slate-300">No jobs yet</h3>
            <p className="mt-2 text-sm text-slate-500">Launch your first scan from a client detail page.</p>
            <Link
              to="/clients"
              className="mt-6 inline-block px-4 py-2 bg-purple-600 text-white rounded-lg hover:bg-purple-700 font-medium transition-colors"
            >
              Go to Clients
            </Link>
          </div>
        )}

        {/* Jobs Table */}
        {!loading && !error && jobs.length > 0 && (
          <div className="bg-slate-800/50 border border-slate-700 rounded-lg overflow-hidden">
            <div className="overflow-x-auto">
              <table className="w-full">
                <thead>
                  <tr className="border-b border-slate-700">
                    <th className="px-6 py-3 text-left text-xs font-medium text-slate-400 uppercase tracking-wider">
                      Job ID
                    </th>
                    <th className="px-6 py-3 text-left text-xs font-medium text-slate-400 uppercase tracking-wider">
                      Kind
                    </th>
                    <th className="px-6 py-3 text-left text-xs font-medium text-slate-400 uppercase tracking-wider">
                      Status
                    </th>
                    <th className="px-6 py-3 text-left text-xs font-medium text-slate-400 uppercase tracking-wider">
                      Created
                    </th>
                    <th className="px-6 py-3 text-left text-xs font-medium text-slate-400 uppercase tracking-wider">
                      Duration
                    </th>
                    <th className="px-6 py-3 text-left text-xs font-medium text-slate-400 uppercase tracking-wider">
                      Attempt
                    </th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-slate-700">
                  {jobs.map((job) => (
                    <tr key={job.id || job.job_id} className="hover:bg-slate-800/30">
                      <td className="px-6 py-4 whitespace-nowrap">
                        <code className="text-sm text-purple-400 font-mono">
                          {String(job.id || job.job_id).slice(0, 8)}...
                        </code>
                      </td>
                      <td className="px-6 py-4 whitespace-nowrap">
                        <span className="text-sm text-white font-medium">
                          {job.kind || job.type || 'unknown'}
                        </span>
                      </td>
                      <td className="px-6 py-4 whitespace-nowrap">
                        <span className={`px-2 py-1 text-xs border rounded ${getStatusBadgeClass(job.status)}`}>
                          {job.status || 'unknown'}
                        </span>
                      </td>
                      <td className="px-6 py-4 whitespace-nowrap text-sm text-slate-300">
                        {job.created_at
                          ? new Date(job.created_at).toLocaleString()
                          : '—'}
                      </td>
                      <td className="px-6 py-4 whitespace-nowrap text-sm text-slate-300">
                        {formatDuration(job.created_at, job.completed_at || job.updated_at)}
                      </td>
                      <td className="px-6 py-4 whitespace-nowrap text-sm text-slate-400">
                        {job.attempt_count || job.retries || 0}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>
        )}

        {/* Stats Summary */}
        {!loading && !error && jobs.length > 0 && (
          <div className="grid grid-cols-2 md:grid-cols-5 gap-4">
            {['queued', 'running', 'completed', 'failed', 'cancelled'].map((status) => {
              const count = jobs.filter((j) => (j.status || '').toLowerCase() === status).length
              return (
                <div
                  key={status}
                  className="p-4 bg-slate-800/50 border border-slate-700 rounded-lg text-center"
                >
                  <div className={`text-2xl font-bold ${getStatusBadgeClass(status).split(' ')[0]}`}>
                    {count}
                  </div>
                  <div className="text-sm text-slate-400 capitalize mt-1">{status}</div>
                </div>
              )
            })}
          </div>
        )}
      </div>
    </PageShell>
  )
}
