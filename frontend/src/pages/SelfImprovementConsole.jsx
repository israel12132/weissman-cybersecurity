import { useState, useEffect, useCallback, useMemo } from 'react'
import { motion, AnimatePresence } from 'framer-motion'
import {
  RefreshCw,
  Play,
  Power,
  CheckCircle2,
  XCircle,
  Cpu,
  Clock,
  GitPullRequest,
  FileText,
  Search,
} from 'lucide-react'
import PageShell from './PageShell'
import EmptyState from '../components/ui/EmptyState'
import { SkeletonWidgetGrid } from '../components/ui/Skeleton'
import { api } from '../utils/apiFetch'
import EvidenceNotice from '../components/ui/EvidenceNotice'
import ShellScanActions from '../components/engine/ShellScanActions'
import { exportRowsCsv, exportRowsPdf, rowMatchesQuery } from '../lib/pageExport'
import Button from '../components/ui/Button'

/** CSV/PDF columns for the self-improvement proposal queue. Exported for tests. */
export const SELF_IMPROVE_CSV_HEADER = ['id', 'category', 'source', 'title', 'status']

/** Pure: proposal items → export rows. Exported for tests. */
export function selfImproveRows(items) {
  return (Array.isArray(items) ? items : []).map((it) => [
    it?.id ?? '',
    it?.category ?? '',
    it?.source ?? '',
    it?.title ?? '',
    it?.status ?? '',
  ])
}

const CATEGORY_LABEL = {
  new_engine: 'New engine',
  improve_engine: 'Improve engine',
  new_module: 'New module',
  improve_module: 'Improve module',
  wiring: 'Smarter wiring',
  sync: 'Better sync',
  gap: 'Close gap',
  cleanliness: 'Cleanliness',
}

const CATEGORY_COLOR = {
  new_engine: 'text-emerald-300 bg-emerald-500/10 border-emerald-500/30',
  improve_engine: 'text-sky-300 bg-sky-500/10 border-sky-500/30',
  new_module: 'text-violet-300 bg-violet-500/10 border-violet-500/30',
  improve_module: 'text-indigo-300 bg-indigo-500/10 border-indigo-500/30',
  wiring: 'text-amber-300 bg-amber-500/10 border-amber-500/30',
  sync: 'text-cyan-300 bg-cyan-500/10 border-cyan-500/30',
  gap: 'text-rose-300 bg-rose-500/10 border-rose-500/30',
  cleanliness: 'text-text-secondary bg-bg-3 border-border-strong',
}

const LEVEL_COLOR = {
  high: 'text-rose-300',
  medium: 'text-amber-300',
  low: 'text-emerald-300',
}

function Level({ label, value }) {
  return (
    <span className="text-[11px] uppercase tracking-wide text-[var(--text-muted)]">
      {label}:{' '}
      <span className={`font-semibold ${LEVEL_COLOR[value] || 'text-[var(--text-secondary)]'}`}>
        {value || '—'}
      </span>
    </span>
  )
}

function StatCard({ icon, label, value, hint }) {
  return (
    <div className="rounded-xl border border-[var(--border-default)] bg-[var(--bg-2)] p-4">
      <div className="flex items-center gap-2 text-[var(--text-muted)] text-xs uppercase tracking-wide">
        {icon}
        {label}
      </div>
      <div className="mt-1 text-2xl font-semibold text-[var(--text-primary)]">{value}</div>
      {hint && <div className="text-[11px] text-[var(--text-muted)] mt-0.5">{hint}</div>}
    </div>
  )
}

export default function SelfImprovementConsole() {
  const [status, setStatus] = useState(null)
  const [items, setItems] = useState([])
  const [filter, setFilter] = useState('PENDING_APPROVAL')
  const [loading, setLoading] = useState(true)
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState(null)
  const [queueUnavailable, setQueueUnavailable] = useState(false)
  const [note, setNote] = useState('')
  const [searchQuery, setSearchQuery] = useState('')

  const load = useCallback(async () => {
    try {
      setError(null)
      const qs = filter ? `?status=${encodeURIComponent(filter)}` : ''
      const [st, q] = await Promise.all([
        api.get('/api/self-improve/status'),
        api.get(`/api/self-improve/queue${qs}`),
      ])
      if (!Array.isArray(q?.items)) {
        throw new Error('Failed to load')
      }
      setQueueUnavailable(false)
      setStatus(st)
      setItems(q.items)
    } catch (e) {
      setError(e?.message || 'Failed to load')
      setQueueUnavailable(true)
    } finally {
      setLoading(false)
    }
  }, [filter])

  useEffect(() => {
    load()
  }, [load])

  const toggle = async () => {
    if (!status) return
    setBusy(true)
    try {
      await api.post('/api/self-improve/toggle', { enabled: !status.enabled })
      await load()
    } catch (e) {
      setError(e?.message || 'Toggle failed')
    } finally {
      setBusy(false)
    }
  }

  const runNow = async () => {
    setBusy(true)
    try {
      await api.post('/api/self-improve/run-now', {})
      await load()
    } catch (e) {
      setError(e?.message || 'Run failed')
    } finally {
      setBusy(false)
    }
  }

  const review = async (id, action) => {
    setBusy(true)
    try {
      await api.post(`/api/self-improve/${id}/${action}`, { review_note: note || null })
      setNote('')
      await load()
    } catch (e) {
      setError(e?.message || `${action} failed`)
    } finally {
      setBusy(false)
    }
  }

  const counts = status?.counts || {}
  const intervalMin = status ? Math.round((status.interval_secs || 3600) / 60) : 60
  const enabled = !!status?.enabled

  // Free-text search over the already status-filtered proposal set (loaded from the queue
  // endpoint). Combines with the existing status filter tabs — no extra server round-trip.
  const filteredItems = useMemo(
    () => items.filter((it) => rowMatchesQuery(searchQuery, [it?.title, it?.category, it?.source])),
    [items, searchQuery],
  )

  const handleRefresh = useCallback(() => load(), [load])
  const exportCsv = useCallback(() => {
    if (queueUnavailable) return
    exportRowsCsv(SELF_IMPROVE_CSV_HEADER, selfImproveRows(filteredItems), 'weissman-self-improvement')
  }, [queueUnavailable, filteredItems])
  const exportPdf = useCallback(() => {
    if (queueUnavailable) return
    exportRowsPdf('Weissman Self-Improvement Console', SELF_IMPROVE_CSV_HEADER, selfImproveRows(filteredItems), 'weissman-self-improvement')
  }, [queueUnavailable, filteredItems])

  return (
    <PageShell
      title="Autonomous Self-Improvement"
      subtitle="An hourly engine that proposes platform improvements. You approve — approval opens a pull request, never touches main."
      icon={<Cpu className="w-5 h-5 text-emerald-400" strokeWidth={1.75} />}
      actions={
        <div className="flex items-center gap-2">
          <Button
            variant="unstyled"
            onClick={runNow}
            disabled={busy}
            className="inline-flex items-center gap-1.5 rounded-lg border border-[var(--border-strong)] bg-[var(--bg-2)] px-3 py-1.5 text-sm text-[var(--text-secondary)] hover:bg-[var(--row-hover-bg)] disabled:opacity-50"
          >
            <Play className="w-4 h-4" /> Run now
          </Button>
          <Button
            variant="unstyled"
            onClick={toggle}
            disabled={busy || !!error}
            className={`inline-flex items-center gap-1.5 rounded-lg px-3 py-1.5 text-sm font-medium disabled:opacity-50 ${
              enabled && !error
                ? 'bg-emerald-500/15 text-emerald-300 border border-emerald-500/40'
                : 'bg-[var(--bg-2)] text-[var(--text-tertiary)] border border-[var(--border-strong)]'
            }`}
          >
            <Power className="w-4 h-4" />
            {error ? 'Status unconfirmed' : enabled ? 'Enabled — click to disable' : 'Disabled — click to enable'}
          </Button>
          <Button
            variant="unstyled"
            onClick={load}
            disabled={busy}
            className="inline-flex items-center rounded-lg border border-[var(--border-strong)] bg-[var(--bg-2)] p-1.5 text-[var(--text-secondary)] hover:bg-[var(--row-hover-bg)] disabled:opacity-50"
            aria-label="Refresh"
          >
            <RefreshCw className={`w-4 h-4 ${busy ? 'animate-spin' : ''}`} />
          </Button>
          <ShellScanActions
            onRefresh={handleRefresh}
            onExport={queueUnavailable ? undefined : exportCsv}
            refreshLoading={loading}
            exportDisabled={queueUnavailable || !filteredItems.length}
          />
          {!queueUnavailable && (
          <Button
            variant="unstyled"
            type="button"
            onClick={exportPdf}
            disabled={!filteredItems.length}
            title="Export PDF"
            className="inline-flex items-center gap-1.5 rounded-lg border border-[var(--border-strong)] bg-[var(--bg-2)] px-3 py-1.5 text-sm text-[var(--text-secondary)] hover:bg-[var(--row-hover-bg)] disabled:opacity-50"
          >
            <FileText className="w-4 h-4" /> PDF
          </Button>
          )}
        </div>
      }
    >
      <div className="mb-4">
        <EvidenceNotice>
          Live queue from GET /api/self-improve/status + /api/self-improve/queue — real proposals
          from the autonomous engine. No fabricated suggestions; exports reflect the loaded rows.
        </EvidenceNotice>
      </div>

      {error && (
        <div className="mb-4 rounded-lg border border-rose-500/30 bg-rose-500/10 px-4 py-2 text-sm text-rose-200">
          {error}
        </div>
      )}

      {loading ? (
        <SkeletonWidgetGrid />
      ) : error ? (
        <div data-testid="self-improvement-unavailable">
          <EmptyState
            icon="alert"
            title="Self-improvement queue unavailable"
            description="GET /api/self-improve/status could not be confirmed. Zero proposals is not a quiet engine."
          />
        </div>
      ) : (
        <>
          <div className="grid grid-cols-2 md:grid-cols-4 gap-3 mb-6">
            <StatCard
              icon={<Power className="w-3.5 h-3.5" />}
              label="Engine"
              value={enabled ? 'Running' : 'Off'}
              hint={`every ${intervalMin} min`}
            />
            <StatCard
              icon={<Clock className="w-3.5 h-3.5" />}
              label="Last cycle"
              value={status?.last_cycle_at ? new Date(status.last_cycle_at).toLocaleString() : '—'}
            />
            <StatCard
              icon={<GitPullRequest className="w-3.5 h-3.5" />}
              label="Pending"
              value={counts.pending ?? 0}
              hint="awaiting your approval"
            />
            <StatCard
              icon={<CheckCircle2 className="w-3.5 h-3.5" />}
              label="Approved / Rejected"
              value={`${counts.approved ?? 0} / ${counts.rejected ?? 0}`}
            />
          </div>

          <div className="flex items-center gap-2 mb-4 flex-wrap">
            {['PENDING_APPROVAL', 'APPROVED', 'REJECTED', 'APPLIED'].map((s) => {
              const n = counts[{ PENDING_APPROVAL: 'pending', APPROVED: 'approved', REJECTED: 'rejected', APPLIED: 'applied' }[s]]
              return (
              <Button
                variant="unstyled"
                key={s}
                onClick={() => setFilter(s)}
                aria-pressed={filter === s}
                className={`rounded-full px-3 py-1 text-xs font-medium border ${
                  filter === s
                    ? 'bg-[var(--bg-2)] text-[var(--text-primary)] border-[var(--border-strong)]'
                    : 'bg-[var(--bg-2)] text-[var(--text-muted)] border-[var(--border-default)] hover:text-[var(--text-primary)]'
                }`}
              >
                {s.replace('_', ' ').toLowerCase()}
                {n != null && <span className="ml-1 opacity-60 tabular-nums">{n}</span>}
              </Button>
              )
            })}
            <div className="relative ml-auto">
              <Search className="w-3.5 h-3.5 text-[var(--text-muted)] absolute left-2.5 top-1/2 -translate-y-1/2 pointer-events-none" />
              <input
                type="search"
                value={searchQuery}
                onChange={(e) => setSearchQuery(e.target.value)}
                placeholder="Search title, category, source"
                aria-label="Search proposals"
                className="w-64 max-w-full pl-8 pr-3 py-1.5 rounded-lg text-xs bg-[var(--table-surface)] border border-[var(--border-default)] text-[var(--text-secondary)] placeholder-[var(--text-muted)] focus:outline-none focus:border-[var(--border-strong)]"
              />
            </div>
          </div>

          {filteredItems.length === 0 ? (
            <EmptyState
              title={searchQuery ? 'No proposals match your search' : 'No proposals in this view'}
              description={
                searchQuery
                  ? 'No proposals match your search in this status. Clear the search or switch tabs.'
                  : enabled
                  ? 'The engine will post proposals on its next hourly cycle. Or click “Run now”.'
                  : 'The engine is disabled. Enable it, or click “Run now” for a one-off analysis.'
              }
            />
          ) : (
            <div className="space-y-3">
              <AnimatePresence>
                {filteredItems.map((it) => {
                  const files = Array.isArray(it.affected_files) ? it.affected_files : []
                  return (
                    <motion.div
                      key={it.id}
                      initial={{ opacity: 0, y: 6 }}
                      animate={{ opacity: 1, y: 0 }}
                      exit={{ opacity: 0 }}
                      className="rounded-xl border border-[var(--border-default)] bg-[var(--bg-2)] p-4"
                    >
                      <div className="flex items-start justify-between gap-4">
                        <div className="min-w-0">
                          <div className="flex items-center gap-2 flex-wrap">
                            <span
                              className={`text-[11px] font-semibold rounded-md border px-2 py-0.5 ${
                                CATEGORY_COLOR[it.category] || 'text-[var(--text-tertiary)] border-[var(--border-strong)]'
                              }`}
                            >
                              {CATEGORY_LABEL[it.category] || it.category}
                            </span>
                            <span className="text-[11px] text-[var(--text-muted)]">
                              {it.source} · #{it.id}
                            </span>
                          </div>
                          <h3 className="mt-1.5 text-[var(--text-primary)] font-medium">{it.title}</h3>
                          {it.rationale && (
                            <p className="mt-1 text-sm text-[var(--text-tertiary)] leading-relaxed">
                              {it.rationale}
                            </p>
                          )}
                          {it.proposed_diff_summary && (
                            <p className="mt-2 text-[13px] text-[var(--text-muted)] border-l-2 border-[var(--border-default)] pl-3">
                              {it.proposed_diff_summary}
                            </p>
                          )}
                          {files.length > 0 && (
                            <div className="mt-2 flex flex-wrap gap-1">
                              {files.map((f, i) => (
                                <code
                                  key={i}
                                  className="text-[11px] text-[var(--text-muted)] bg-[var(--table-surface)] rounded px-1.5 py-0.5"
                                >
                                  {f}
                                </code>
                              ))}
                            </div>
                          )}
                          <div className="mt-2 flex items-center gap-4">
                            <Level label="risk" value={it.risk} />
                            <Level label="impact" value={it.impact} />
                            <Level label="effort" value={it.effort} />
                          </div>
                        </div>
                        {it.status === 'PENDING_APPROVAL' && (
                          <div className="flex flex-col gap-2 shrink-0">
                            <Button
                              variant="unstyled"
                              onClick={() => review(it.id, 'approve')}
                              disabled={busy}
                              className="inline-flex items-center gap-1.5 rounded-lg bg-emerald-500/15 text-emerald-300 border border-emerald-500/40 px-3 py-1.5 text-sm hover:bg-emerald-500/25 disabled:opacity-50"
                            >
                              <CheckCircle2 className="w-4 h-4" /> Approve → PR
                            </Button>
                            <Button
                              variant="unstyled"
                              onClick={() => review(it.id, 'reject')}
                              disabled={busy}
                              className="inline-flex items-center gap-1.5 rounded-lg bg-[var(--bg-2)] text-[var(--text-tertiary)] border border-[var(--border-strong)] px-3 py-1.5 text-sm hover:bg-[var(--row-hover-bg)] disabled:opacity-50"
                            >
                              <XCircle className="w-4 h-4" /> Reject
                            </Button>
                          </div>
                        )}
                        {it.status !== 'PENDING_APPROVAL' && (
                          <span className="text-xs text-[var(--text-muted)] shrink-0">{it.status}</span>
                        )}
                      </div>
                      {it.pr_url && (
                        <a
                          href={it.pr_url}
                          target="_blank"
                          rel="noreferrer"
                          className="mt-2 inline-flex items-center gap-1 text-xs text-sky-300 underline"
                        >
                          <GitPullRequest className="w-3.5 h-3.5" /> View pull request
                        </a>
                      )}
                    </motion.div>
                  )
                })}
              </AnimatePresence>
              {filter === 'PENDING_APPROVAL' && filteredItems.length > 0 && (
                <div className="pt-2">
                  <input
                    value={note}
                    onChange={(e) => setNote(e.target.value)}
                    aria-label="Optional review note applied to your next approve or reject"
                    placeholder="Optional review note (applied to your next approve/reject)"
                    className="w-full rounded-lg border border-[var(--border-default)] bg-[var(--table-surface)] px-3 py-2 text-sm text-[var(--text-secondary)] placeholder-[var(--text-muted)]"
                  />
                </div>
              )}
            </div>
          )}
        </>
      )}
    </PageShell>
  )
}
