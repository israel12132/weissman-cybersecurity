import { useState, useEffect, useCallback } from 'react'
import { motion, AnimatePresence } from 'framer-motion'
import {
  Play,
  Power,
  CheckCircle2,
  XCircle,
  Cpu,
  Clock,
  GitPullRequest,
} from 'lucide-react'
import PageShell from './PageShell'
import ShellScanActions from '../components/engine/ShellScanActions'
import { downloadCsv } from '../lib/exportFindingsCsv'
import EmptyState from '../components/ui/EmptyState'
import { SkeletonWidgetGrid } from '../components/ui/Skeleton'
import { api } from '../utils/apiFetch'

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
  cleanliness: 'text-slate-300 bg-slate-500/10 border-slate-500/30',
}

const LEVEL_COLOR = {
  high: 'text-rose-300',
  medium: 'text-amber-300',
  low: 'text-emerald-300',
}

function Level({ label, value }) {
  return (
    <span className="text-[11px] uppercase tracking-wide text-white/40">
      {label}:{' '}
      <span className={`font-semibold ${LEVEL_COLOR[value] || 'text-white/70'}`}>
        {value || '—'}
      </span>
    </span>
  )
}

function StatCard({ icon, label, value, hint }) {
  return (
    <div className="rounded-xl border border-white/10 bg-white/[0.03] p-4">
      <div className="flex items-center gap-2 text-white/50 text-xs uppercase tracking-wide">
        {icon}
        {label}
      </div>
      <div className="mt-1 text-2xl font-semibold text-white">{value}</div>
      {hint && <div className="text-[11px] text-white/40 mt-0.5">{hint}</div>}
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
  const [note, setNote] = useState('')
  const [searchQuery, setSearchQuery] = useState('')

  const exportProposals = () => {
    downloadCsv(
      (items || []).map((it) => [
        it.id,
        it.title || it.summary || '',
        it.status || '',
        (Array.isArray(it.affected_files) ? it.affected_files : []).join('; '),
      ]),
      ['id', 'title', 'status', 'affected_files'],
      'weissman-self-improve-proposals',
    )
  }

  const load = useCallback(async () => {
    try {
      setError(null)
      const qs = filter ? `?status=${encodeURIComponent(filter)}` : ''
      const [st, q] = await Promise.all([
        api.get('/api/self-improve/status'),
        api.get(`/api/self-improve/queue${qs}`),
      ])
      setStatus(st)
      setItems(Array.isArray(q?.items) ? q.items : [])
    } catch (e) {
      setError(e?.message || 'Failed to load')
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

  const visibleItems = (items || []).filter(
    (it) =>
      !searchQuery ||
      [it.id, it.title, it.summary, it.status].some((x) =>
        String(x || '').toLowerCase().includes(searchQuery.toLowerCase()),
      ),
  )

  return (
    <PageShell
      title="Autonomous Self-Improvement"
      subtitle="An hourly engine that proposes platform improvements. You approve — approval opens a pull request, never touches main."
      icon={<Cpu className="w-5 h-5 text-emerald-400" strokeWidth={1.75} />}
      actions={
        <div className="flex items-center gap-2">
          <button
            onClick={runNow}
            disabled={busy}
            className="inline-flex items-center gap-1.5 rounded-lg border border-white/15 bg-white/5 px-3 py-1.5 text-sm text-white/80 hover:bg-white/10 disabled:opacity-50"
          >
            <Play className="w-4 h-4" /> Run now
          </button>
          <button
            onClick={toggle}
            disabled={busy}
            className={`inline-flex items-center gap-1.5 rounded-lg px-3 py-1.5 text-sm font-medium disabled:opacity-50 ${
              enabled
                ? 'bg-emerald-500/15 text-emerald-300 border border-emerald-500/40'
                : 'bg-white/5 text-white/60 border border-white/15'
            }`}
          >
            <Power className="w-4 h-4" />
            {enabled ? 'Enabled — click to disable' : 'Disabled — click to enable'}
          </button>
          <ShellScanActions onRefresh={load} refreshLoading={busy} onExport={exportProposals} />
        </div>
      }
    >
      {error && (
        <div className="mb-4 rounded-lg border border-rose-500/30 bg-rose-500/10 px-4 py-2 text-sm text-rose-200">
          {error}
        </div>
      )}

      {loading ? (
        <SkeletonWidgetGrid />
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
            {['PENDING_APPROVAL', 'APPROVED', 'REJECTED', 'APPLIED'].map((s) => (
              <button
                key={s}
                onClick={() => setFilter(s)}
                className={`rounded-full px-3 py-1 text-xs font-medium border ${
                  filter === s
                    ? 'bg-white/15 text-white border-white/30'
                    : 'bg-white/[0.03] text-white/50 border-white/10 hover:text-white/80'
                }`}
              >
                {s.replace('_', ' ').toLowerCase()}
              </button>
            ))}
            <input
              type="search"
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
              aria-label="Search"
              placeholder="Search"
              className="ml-auto w-44 rounded-lg border border-white/10 bg-white/5 px-2.5 py-1 text-xs font-mono text-white/80 placeholder-white/25 focus:outline-none focus:ring-2 focus:ring-emerald-500/40"
            />
          </div>

          {visibleItems.length === 0 ? (
            <EmptyState
              title="No proposals in this view"
              description={
                enabled
                  ? 'The engine will post proposals on its next hourly cycle. Or click “Run now”.'
                  : 'The engine is disabled. Enable it, or click “Run now” for a one-off analysis.'
              }
            />
          ) : (
            <div className="space-y-3">
              <AnimatePresence>
                {visibleItems.map((it) => {
                  const files = Array.isArray(it.affected_files) ? it.affected_files : []
                  return (
                    <motion.div
                      key={it.id}
                      initial={{ opacity: 0, y: 6 }}
                      animate={{ opacity: 1, y: 0 }}
                      exit={{ opacity: 0 }}
                      className="rounded-xl border border-white/10 bg-white/[0.03] p-4"
                    >
                      <div className="flex items-start justify-between gap-4">
                        <div className="min-w-0">
                          <div className="flex items-center gap-2 flex-wrap">
                            <span
                              className={`text-[11px] font-semibold rounded-md border px-2 py-0.5 ${
                                CATEGORY_COLOR[it.category] || 'text-white/60 border-white/15'
                              }`}
                            >
                              {CATEGORY_LABEL[it.category] || it.category}
                            </span>
                            <span className="text-[11px] text-white/30">
                              {it.source} · #{it.id}
                            </span>
                          </div>
                          <h3 className="mt-1.5 text-white font-medium">{it.title}</h3>
                          {it.rationale && (
                            <p className="mt-1 text-sm text-white/60 leading-relaxed">
                              {it.rationale}
                            </p>
                          )}
                          {it.proposed_diff_summary && (
                            <p className="mt-2 text-[13px] text-white/50 border-l-2 border-white/10 pl-3">
                              {it.proposed_diff_summary}
                            </p>
                          )}
                          {files.length > 0 && (
                            <div className="mt-2 flex flex-wrap gap-1">
                              {files.map((f, i) => (
                                <code
                                  key={i}
                                  className="text-[11px] text-white/45 bg-black/30 rounded px-1.5 py-0.5"
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
                            <button
                              onClick={() => review(it.id, 'approve')}
                              disabled={busy}
                              className="inline-flex items-center gap-1.5 rounded-lg bg-emerald-500/15 text-emerald-300 border border-emerald-500/40 px-3 py-1.5 text-sm hover:bg-emerald-500/25 disabled:opacity-50"
                            >
                              <CheckCircle2 className="w-4 h-4" /> Approve → PR
                            </button>
                            <button
                              onClick={() => review(it.id, 'reject')}
                              disabled={busy}
                              className="inline-flex items-center gap-1.5 rounded-lg bg-white/5 text-white/60 border border-white/15 px-3 py-1.5 text-sm hover:bg-white/10 disabled:opacity-50"
                            >
                              <XCircle className="w-4 h-4" /> Reject
                            </button>
                          </div>
                        )}
                        {it.status !== 'PENDING_APPROVAL' && (
                          <span className="text-xs text-white/40 shrink-0">{it.status}</span>
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
              {filter === 'PENDING_APPROVAL' && items.length > 0 && (
                <div className="pt-2">
                  <input
                    value={note}
                    onChange={(e) => setNote(e.target.value)}
                    placeholder="Optional review note (applied to your next approve/reject)"
                    className="w-full rounded-lg border border-white/10 bg-black/30 px-3 py-2 text-sm text-white/80 placeholder-white/30"
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
