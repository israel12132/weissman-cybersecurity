import React, { useState, useEffect, useCallback } from 'react'
import { motion, AnimatePresence } from 'framer-motion'
import PageShell from './PageShell'
import { apiFetch } from '../lib/apiBase'

const STATUS_COLORS = {
  PENDING_APPROVAL: 'text-amber-400 border-amber-400/30 bg-amber-900/10',
  APPROVED: 'text-green-400 border-green-400/30 bg-green-900/10',
  FIRED: 'text-cyan-400 border-cyan-400/30 bg-cyan-900/10',
  REJECTED: 'text-rose-400 border-rose-400/30 bg-rose-900/10',
  FAILED: 'text-red-500 border-red-500/30 bg-red-900/10',
}

const SEV_COLORS = {
  critical: 'text-red-400',
  high: 'text-orange-400',
  medium: 'text-amber-400',
  low: 'text-green-400',
}

function StatusBadge({ status }) {
  const cls = STATUS_COLORS[status] ?? 'text-white/40 border-white/10'
  return (
    <span className={`text-[10px] font-mono uppercase px-2 py-0.5 rounded border ${cls}`}>
      {status?.replace('_', ' ')}
    </span>
  )
}

function ChainSteps({ steps }) {
  if (!Array.isArray(steps) || steps.length === 0) return <span className="text-white/30 text-[11px]">—</span>
  return (
    <ol className="list-decimal list-inside space-y-0.5">
      {steps.map((s, i) => (
        <li key={i} className="text-[11px] text-white/60 leading-relaxed">{s}</li>
      ))}
    </ol>
  )
}

function HitlItem({ item, onApprove, onReject, loading }) {
  const [expanded, setExpanded] = useState(false)
  const [note, setNote] = useState('')
  const isPending = item.status === 'PENDING_APPROVAL'
  const severityClass = SEV_COLORS[item.estimated_severity] ?? 'text-white/50'

  return (
    <motion.div
      layout
      initial={{ opacity: 0, y: 8 }}
      animate={{ opacity: 1, y: 0 }}
      exit={{ opacity: 0, y: -4 }}
      className="rounded-2xl bg-black/40 backdrop-blur-md border border-white/10 p-5 space-y-4"
    >
      {/* Header row */}
      <div className="flex items-start justify-between gap-3 flex-wrap">
        <div className="space-y-1 min-w-0">
          <div className="flex items-center gap-2 flex-wrap">
            <span className="text-[11px] font-mono text-white/30">#{item.id}</span>
            <StatusBadge status={item.status} />
            <span className={`text-[11px] font-semibold uppercase ${severityClass}`}>
              {item.estimated_severity}
            </span>
          </div>
          <p className="text-sm font-medium text-white truncate max-w-lg">{item.target_brief}</p>
          <p className="text-[10px] font-mono text-white/25">
            {item.proposed_at ? new Date(item.proposed_at).toLocaleString() : ''}
            {item.client_id ? ` · client ${item.client_id}` : ''}
          </p>
        </div>
        <button
          type="button"
          onClick={() => setExpanded(v => !v)}
          className="shrink-0 text-[11px] font-mono text-white/40 hover:text-white/70 transition-colors px-3 py-1.5 rounded-lg border border-white/10 hover:border-white/20"
        >
          {expanded ? '▲ collapse' : '▼ details'}
        </button>
      </div>

      {/* Expanded section */}
      <AnimatePresence>
        {expanded && (
          <motion.div
            initial={{ opacity: 0, height: 0 }}
            animate={{ opacity: 1, height: 'auto' }}
            exit={{ opacity: 0, height: 0 }}
            className="overflow-hidden space-y-4"
          >
            {/* Chain steps */}
            <div>
              <p className="text-[10px] font-mono text-white/30 uppercase mb-1">Chain Steps</p>
              <div className="rounded-xl bg-white/5 border border-white/10 p-3">
                <ChainSteps steps={item.chain_steps} />
              </div>
            </div>

            {/* Payload preview */}
            {item.payload_preview && (
              <div>
                <p className="text-[10px] font-mono text-white/30 uppercase mb-1">Payload Preview (safe excerpt)</p>
                <pre className="rounded-xl bg-white/5 border border-white/10 p-3 text-[11px] font-mono text-cyan-300/70 whitespace-pre-wrap break-words max-h-40 overflow-y-auto">
                  {item.payload_preview}
                </pre>
              </div>
            )}

            {/* Rationale */}
            {item.rationale && (
              <div>
                <p className="text-[10px] font-mono text-white/30 uppercase mb-1">Rationale</p>
                <p className="text-[11px] text-white/55 leading-relaxed">{item.rationale}</p>
              </div>
            )}

            {/* Fired job link */}
            {item.fired_job_id && (
              <p className="text-[11px] font-mono text-cyan-400/70">
                Fired job: <a href={`/api/jobs/${item.fired_job_id}`} className="underline" target="_blank" rel="noreferrer">{item.fired_job_id}</a>
              </p>
            )}
            {item.review_note && (
              <p className="text-[11px] text-white/40 italic">Note: {item.review_note}</p>
            )}
          </motion.div>
        )}
      </AnimatePresence>

      {/* Approval controls (only for PENDING) */}
      {isPending && (
        <div className="flex flex-col sm:flex-row gap-3 pt-1">
          <input
            type="text"
            placeholder="Operator note (optional)"
            value={note}
            onChange={e => setNote(e.target.value)}
            className="flex-1 rounded-xl bg-white/5 border border-white/10 px-3 py-1.5 text-[12px] text-white/70 placeholder-white/20 focus:outline-none focus:border-cyan-500/40"
          />
          <button
            type="button"
            disabled={loading}
            onClick={() => onApprove(item.id, note)}
            className="px-4 py-1.5 rounded-xl text-[12px] font-semibold font-mono uppercase border border-green-500/40 text-green-400 hover:bg-green-900/20 disabled:opacity-40 disabled:cursor-not-allowed transition-all"
          >
            ✓ Approve & Fire
          </button>
          <button
            type="button"
            disabled={loading}
            onClick={() => onReject(item.id, note)}
            className="px-4 py-1.5 rounded-xl text-[12px] font-semibold font-mono uppercase border border-rose-500/40 text-rose-400 hover:bg-rose-900/20 disabled:opacity-40 disabled:cursor-not-allowed transition-all"
          >
            ✗ Reject
          </button>
        </div>
      )}
    </motion.div>
  )
}

const STATUS_TABS = ['ALL', 'PENDING_APPROVAL', 'FIRED', 'REJECTED']

export default function CouncilHitlQueue() {
  const [items, setItems] = useState([])
  const [loading, setLoading] = useState(false)
  const [activeTab, setActiveTab] = useState('PENDING_APPROVAL')
  const [toast, setToast] = useState(null)

  const showToast = useCallback((msg, ok = true) => {
    setToast({ msg, ok })
    setTimeout(() => setToast(null), 4000)
  }, [])

  const fetchQueue = useCallback(async () => {
    const qs = activeTab === 'ALL' ? '' : `?status=${activeTab}`
    try {
      const data = await apiFetch(`/api/council/hitl/queue${qs}`)
      setItems(data.items ?? [])
    } catch (e) {
      showToast('Failed to load queue: ' + e.message, false)
    }
  }, [activeTab, showToast])

  useEffect(() => { fetchQueue() }, [fetchQueue])

  const handleApprove = useCallback(async (id, note) => {
    setLoading(true)
    try {
      const data = await apiFetch(`/api/council/hitl/${id}/approve`, {
        method: 'POST',
        body: JSON.stringify({ review_note: note || null }),
      })
      showToast(`Approved & fired — job ${data.job_id?.slice(0, 8)}…`)
      await fetchQueue()
    } catch (e) {
      showToast('Approval failed: ' + e.message, false)
    } finally {
      setLoading(false)
    }
  }, [fetchQueue, showToast])

  const handleReject = useCallback(async (id, note) => {
    setLoading(true)
    try {
      await apiFetch(`/api/council/hitl/${id}/reject`, {
        method: 'POST',
        body: JSON.stringify({ review_note: note || null }),
      })
      showToast('Proposal rejected.')
      await fetchQueue()
    } catch (e) {
      showToast('Rejection failed: ' + e.message, false)
    } finally {
      setLoading(false)
    }
  }, [fetchQueue, showToast])

  const pending = items.filter(i => i.status === 'PENDING_APPROVAL').length

  return (
    <PageShell>
      <div className="min-h-screen bg-[#050b14] text-white">
        <div className="max-w-4xl mx-auto px-4 py-10 space-y-8">

          {/* Header */}
          <div className="space-y-1">
            <div className="flex items-center gap-3">
              <h1 className="text-xl font-bold text-white tracking-tight">Council HITL Queue</h1>
              {pending > 0 && (
                <span className="relative flex items-center gap-1 px-2 py-0.5 rounded-full bg-amber-500/10 border border-amber-500/30 text-amber-400 text-[11px] font-mono">
                  <span className="relative flex w-1.5 h-1.5">
                    <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-amber-400 opacity-60" />
                    <span className="relative inline-flex rounded-full w-1.5 h-1.5 bg-amber-400" />
                  </span>
                  {pending} pending
                </span>
              )}
            </div>
            <p className="text-[12px] text-white/40">
              Review Council-proposed attack chains before they are executed. Safety rails (no shells) are always enforced.
            </p>
          </div>

          {/* Safety notice */}
          <div className="rounded-2xl bg-green-900/10 border border-green-500/20 px-4 py-3 flex items-start gap-3">
            <span className="text-green-400 mt-0.5">🔒</span>
            <div>
              <p className="text-[12px] font-semibold text-green-300">Safety rails active</p>
              <p className="text-[11px] text-white/40 mt-0.5">
                <code className="font-mono">safety_rails_no_shells = true</code> is enforced on every fired job. No shell payloads, stagers, or reverse connections are generated. Approval triggers OOB/OAST-safe benign proof-of-concept only.
              </p>
            </div>
          </div>

          {/* Tabs */}
          <div className="flex gap-1 flex-wrap">
            {STATUS_TABS.map(tab => (
              <button
                key={tab}
                type="button"
                onClick={() => setActiveTab(tab)}
                className={`px-3 py-1.5 rounded-xl text-[11px] font-mono uppercase border transition-all ${
                  activeTab === tab
                    ? 'bg-cyan-900/20 border-cyan-500/40 text-cyan-300'
                    : 'border-white/10 text-white/40 hover:border-white/20 hover:text-white/60'
                }`}
              >
                {tab.replace('_', ' ')}
              </button>
            ))}
            <button
              type="button"
              onClick={fetchQueue}
              className="ml-auto px-3 py-1.5 rounded-xl text-[11px] font-mono border border-white/10 text-white/40 hover:border-white/20 hover:text-white/60 transition-all"
            >
              ↻ Refresh
            </button>
          </div>

          {/* Queue items */}
          <div className="space-y-4">
            <AnimatePresence>
              {items.length === 0 ? (
                <motion.p
                  initial={{ opacity: 0 }}
                  animate={{ opacity: 1 }}
                  className="text-center text-white/25 text-[12px] py-16"
                >
                  No items in this queue
                </motion.p>
              ) : (
                items.map(item => (
                  <HitlItem
                    key={item.id}
                    item={item}
                    onApprove={handleApprove}
                    onReject={handleReject}
                    loading={loading}
                  />
                ))
              )}
            </AnimatePresence>
          </div>
        </div>

        {/* Toast */}
        <AnimatePresence>
          {toast && (
            <motion.div
              initial={{ opacity: 0, y: 16 }}
              animate={{ opacity: 1, y: 0 }}
              exit={{ opacity: 0, y: 16 }}
              className={`fixed bottom-6 right-6 px-4 py-3 rounded-2xl border text-[12px] font-mono z-50 ${
                toast.ok
                  ? 'bg-green-900/40 border-green-500/30 text-green-300'
                  : 'bg-red-900/40 border-red-500/30 text-red-300'
              }`}
            >
              {toast.msg}
            </motion.div>
          )}
        </AnimatePresence>
      </div>
    </PageShell>
  )
}
