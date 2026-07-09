import { useState, useEffect, useCallback, useMemo } from 'react'
import { useTranslation } from 'react-i18next'
import { motion, AnimatePresence } from 'framer-motion'
import { Search, ShieldCheck } from 'lucide-react';
import PageShell from './PageShell'
import ShellScanActions from '../components/engine/ShellScanActions'
import { useFindingsWorkbench } from '../hooks/useFindingsWorkbench'
import EvidenceNotice from '../components/ui/EvidenceNotice'
import EmptyState from '../components/ui/EmptyState'
import { SkeletonWidgetGrid } from '../components/ui/Skeleton'
import { apiUrl } from '../lib/apiBase'
import { api } from '../utils/apiFetch'

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

const STATUS_TABS = ['ALL', 'PENDING_APPROVAL', 'FIRED', 'REJECTED']

const TAB_I18N = {
  ALL: 'tab_all',
  PENDING_APPROVAL: 'tab_pending_approval',
  FIRED: 'tab_fired',
  REJECTED: 'tab_rejected',
}

function statusI18nKey(status) {
  return `pages.councilHitlQueue.status_${status}`
}

function exportQueueCsv(items) {
  const header = ['id', 'status', 'estimated_severity', 'target_brief', 'client_id', 'proposed_at', 'fired_job_id']
  const esc = (v) => `"${String(v ?? '').replace(/"/g, '""')}"`
  const lines = [
    header.join(','),
    ...items.map((item) =>
      [
        item.id,
        item.status,
        item.estimated_severity,
        item.target_brief,
        item.client_id,
        item.proposed_at,
        item.fired_job_id,
      ].map(esc).join(','),
    ),
  ]
  const blob = new Blob([lines.join('\n')], { type: 'text/csv;charset=utf-8' })
  const url = URL.createObjectURL(blob)
  const a = document.createElement('a')
  a.href = url
  a.download = `weissman-hitl-queue-${new Date().toISOString().slice(0, 10)}.csv`
  a.click()
  URL.revokeObjectURL(url)
}

function StatusBadge({ status }) {
  const { t } = useTranslation()
  const cls = STATUS_COLORS[status] ?? 'text-[var(--text-muted)] border-[var(--border-default)]'
  const label = t(statusI18nKey(status), { defaultValue: status?.replace(/_/g, ' ') })
  return (
    <span className={`text-[10px] font-mono uppercase px-2 py-0.5 rounded border ${cls}`}>
      {label}
    </span>
  )
}

function ChainSteps({ steps }) {
  if (!Array.isArray(steps) || steps.length === 0) {
    return <span className="text-[var(--text-disabled)] text-[11px]">—</span>
  }
  return (
    <ol className="list-decimal list-inside space-y-0.5">
      {steps.map((s, i) => (
        <li key={i} className="text-[11px] text-[var(--text-tertiary)] leading-relaxed">{s}</li>
      ))}
    </ol>
  )
}

function HitlItem({ item, onApprove, onReject, loading }) {
  const { t } = useTranslation()
  const [expanded, setExpanded] = useState(false)
  const [note, setNote] = useState('')
  const isPending = item.status === 'PENDING_APPROVAL'
  const sevKey = (item.estimated_severity || '').toLowerCase()
  const severityClass = SEV_COLORS[sevKey] ?? 'text-[var(--text-tertiary)]'
  const severityLabel = t(`pages.councilHitlQueue.sev_${sevKey}`, {
    defaultValue: item.estimated_severity,
  })

  return (
    <motion.div
      layout
      initial={{ opacity: 0, y: 8 }}
      animate={{ opacity: 1, y: 0 }}
      exit={{ opacity: 0, y: -4 }}
      className="rounded-2xl bg-[var(--bg-2)] backdrop-blur-md border border-[var(--border-default)] p-5 space-y-4"
    >
      <div className="flex items-start justify-between gap-3 flex-wrap">
        <div className="space-y-1 min-w-0">
          <div className="flex items-center gap-2 flex-wrap">
            <span className="text-[11px] font-mono text-[var(--text-disabled)]">#{item.id}</span>
            <StatusBadge status={item.status} />
            <span className={`text-[11px] font-semibold uppercase ${severityClass}`}>
              {severityLabel}
            </span>
          </div>
          <p className="text-sm font-medium text-white truncate max-w-lg">{item.target_brief}</p>
          <p className="text-[10px] font-mono text-[var(--text-disabled)]">
            {item.proposed_at ? new Date(item.proposed_at).toLocaleString() : ''}
            {item.client_id ? t('pages.councilHitlQueue.client_suffix', { id: item.client_id }) : ''}
          </p>
        </div>
        <button
          type="button"
          onClick={() => setExpanded(v => !v)}
          className="shrink-0 text-[11px] font-mono text-[var(--text-muted)] hover:text-[var(--text-secondary)] transition-colors px-3 py-1.5 rounded-lg border border-[var(--border-default)] hover:border-[var(--border-strong)]"
        >
          {expanded ? t('pages.councilHitlQueue.collapse') : t('pages.councilHitlQueue.details')}
        </button>
      </div>

      <AnimatePresence>
        {expanded && (
          <motion.div
            initial={{ opacity: 0, height: 0 }}
            animate={{ opacity: 1, height: 'auto' }}
            exit={{ opacity: 0, height: 0 }}
            className="overflow-hidden space-y-4"
          >
            <div>
              <p className="text-[10px] font-mono text-[var(--text-disabled)] uppercase mb-1">{t('pages.councilHitlQueue.chain_steps')}</p>
              <div className="rounded-xl bg-[var(--row-hover-bg)] border border-[var(--border-default)] p-3">
                <ChainSteps steps={item.chain_steps} />
              </div>
            </div>

            {item.payload_preview && (
              <div>
                <p className="text-[10px] font-mono text-[var(--text-disabled)] uppercase mb-1">{t('pages.councilHitlQueue.payload_preview')}</p>
                <pre className="rounded-xl bg-[var(--row-hover-bg)] border border-[var(--border-default)] p-3 text-[11px] font-mono text-cyan-300/70 whitespace-pre-wrap break-words max-h-40 overflow-y-auto">
                  {item.payload_preview}
                </pre>
              </div>
            )}

            {item.rationale && (
              <div>
                <p className="text-[10px] font-mono text-[var(--text-disabled)] uppercase mb-1">{t('pages.councilHitlQueue.rationale')}</p>
                <p className="text-[11px] text-[var(--text-tertiary)] leading-relaxed">{item.rationale}</p>
              </div>
            )}

            {item.fired_job_id && (
              <p className="text-[11px] font-mono text-cyan-400/70">
                {t('pages.councilHitlQueue.fired_job')}{' '}
                <a href={apiUrl(`/api/jobs/${item.fired_job_id}`)} className="underline" target="_blank" rel="noreferrer">{item.fired_job_id}</a>
              </p>
            )}
            {item.review_note && (
              <p className="text-[11px] text-[var(--text-muted)] italic">{t('pages.councilHitlQueue.review_note', { note: item.review_note })}</p>
            )}
          </motion.div>
        )}
      </AnimatePresence>

      {isPending && (
        <div className="flex flex-col sm:flex-row gap-3 pt-1">
          <input
            type="text"
            placeholder={t('pages.councilHitlQueue.operator_note')}
            value={note}
            onChange={e => setNote(e.target.value)}
            className="flex-1 rounded-xl bg-[var(--row-hover-bg)] border border-[var(--border-default)] px-3 py-1.5 text-[12px] text-[var(--text-secondary)] placeholder-white/20 focus:outline-none focus:border-cyan-500/40"
          />
          <button
            type="button"
            disabled={loading}
            onClick={() => onApprove(item.id, note)}
            className="px-4 py-1.5 rounded-xl text-[12px] font-semibold font-mono uppercase border border-green-500/40 text-green-400 hover:bg-green-900/20 disabled:opacity-40 disabled:cursor-not-allowed transition-all"
          >
            {t('pages.councilHitlQueue.approve_fire')}
          </button>
          <button
            type="button"
            disabled={loading}
            onClick={() => onReject(item.id, note)}
            className="px-4 py-1.5 rounded-xl text-[12px] font-semibold font-mono uppercase border border-rose-500/40 text-rose-400 hover:bg-rose-900/20 disabled:opacity-40 disabled:cursor-not-allowed transition-all"
          >
            {t('pages.councilHitlQueue.reject')}
          </button>
        </div>
      )}
    </motion.div>
  )
}

export default function CouncilHitlQueue() {
  const { t } = useTranslation()
  const [items, setItems] = useState([])
  const [fetchLoading, setFetchLoading] = useState(true)
  const [actionLoading, setActionLoading] = useState(false)
  const [activeTab, setActiveTab] = useState('PENDING_APPROVAL')
  const [search, setSearch] = useState('')
  const [toast, setToast] = useState(null)

  const showToast = useCallback((msg, ok = true) => {
    setToast({ msg, ok })
    setTimeout(() => setToast(null), 4000)
  }, [])

  const fetchQueue = useCallback(async () => {
    const qs = activeTab === 'ALL' ? '' : `?status=${activeTab}`
    setFetchLoading(true)
    try {
      const data = await api.get(`/api/council/hitl/queue${qs}`)
      setItems(data.items ?? [])
    } catch (e) {
      showToast(t('pages.councilHitlQueue.load_failed', { message: e.message }), false)
    } finally {
      setFetchLoading(false)
    }
  }, [activeTab, showToast, t])

  useEffect(() => { fetchQueue() }, [fetchQueue])

  const handleApprove = useCallback(async (id, note) => {
    setActionLoading(true)
    try {
      const data = await api.post(`/api/council/hitl/${id}/approve`, { review_note: note || null })
      showToast(t('pages.councilHitlQueue.approved_toast', { jobId: data.job_id?.slice(0, 8) }))
      await fetchQueue()
    } catch (e) {
      showToast(t('pages.councilHitlQueue.approval_failed', { message: e.message }), false)
    } finally {
      setActionLoading(false)
    }
  }, [fetchQueue, showToast, t])

  const handleReject = useCallback(async (id, note) => {
    setActionLoading(true)
    try {
      await api.post(`/api/council/hitl/${id}/reject`, { review_note: note || null })
      showToast(t('pages.councilHitlQueue.rejected_toast'))
      await fetchQueue()
    } catch (e) {
      showToast(t('pages.councilHitlQueue.rejection_failed', { message: e.message }), false)
    } finally {
      setActionLoading(false)
    }
  }, [fetchQueue, showToast, t])

  const pending = items.filter(i => i.status === 'PENDING_APPROVAL').length

  const filteredItems = useMemo(() => {
    const q = search.trim().toLowerCase()
    if (!q) return items
    return items.filter((item) => {
      const hay = [
        item.id,
        item.target_brief,
        item.client_id,
        item.status,
        item.estimated_severity,
      ]
        .filter(Boolean)
        .join(' ')
        .toLowerCase()
      return hay.includes(q)
    })
  }, [items, search])

  const listFindings = useMemo(() => filteredItems.map((item) => ({
    id: item.id,
    severity: (item.estimated_severity || 'medium').toLowerCase(),
    title: item.target_brief || `#${item.id}`,
    type: item.status || 'hitl',
    description: item.proposed_at ? new Date(item.proposed_at).toLocaleString() : '',
    resource: String(item.client_id ?? ''),
  })), [filteredItems])

  const { filteredFindings } = useFindingsWorkbench(listFindings, {
    csvPrefix: 'weissman-hitl-queue',
    haystackFn: (f) => `${f.title} ${f.type} ${f.description} ${f.resource}`,
  })

  const headerActions = (
    <ShellScanActions
      onRefresh={fetchQueue}
      onExport={() => exportQueueCsv(filteredItems)}
      refreshLoading={fetchLoading}
      exportDisabled={!filteredFindings.length}
    />
  )

  return (
    <PageShell
      title={t('pages.councilHitlQueue.title')}
      subtitle={t('pages.councilHitlQueue.subtitle')}
      icon={<ShieldCheck className="w-5 h-5 text-amber-400" strokeWidth={1.75} />}
      badge={pending > 0 ? t('pages.councilHitlQueue.pending_badge', { count: pending }) : undefined}
      badgeColor="#fbbf24"
      actions={headerActions}
      maxWidth="max-w-4xl"
    >
      <div className="space-y-6">
        <EvidenceNotice>{t('pages.councilHitlQueue.evidence_notice')}</EvidenceNotice>

        <div className="rounded-2xl bg-green-900/10 border border-green-500/20 px-4 py-3 flex items-start gap-3">
          <span className="text-green-400 mt-0.5">🔒</span>
          <div>
            <p className="text-[12px] font-semibold text-green-300">{t('pages.councilHitlQueue.safety_title')}</p>
            <p className="text-[11px] text-[var(--text-muted)] mt-0.5">
              {t('pages.councilHitlQueue.safety_body')}
            </p>
          </div>
        </div>

        <div className="flex gap-1 flex-wrap items-center">
          {STATUS_TABS.map(tab => (
            <button
              key={tab}
              type="button"
              onClick={() => setActiveTab(tab)}
              className={`px-3 py-1.5 rounded-xl text-[11px] font-mono uppercase border transition-all ${
                activeTab === tab
                  ? 'bg-cyan-900/20 border-cyan-500/40 text-cyan-300'
                  : 'border-[var(--border-default)] text-[var(--text-muted)] hover:border-[var(--border-strong)] hover:text-[var(--text-tertiary)]'
              }`}
            >
              {t(`pages.councilHitlQueue.${TAB_I18N[tab]}`)}
            </button>
          ))}
        </div>

        <div className="relative">
          <Search className="absolute start-3 top-1/2 -translate-y-1/2 w-4 h-4 text-[var(--text-disabled)] pointer-events-none" />
          <input
            type="search"
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            placeholder={t('pages.councilHitlQueue.search_placeholder')}
            aria-label={t('pages.councilHitlQueue.search_placeholder')}
            className="w-full rounded-xl bg-[var(--row-hover-bg)] border border-[var(--border-default)] ps-10 pe-3 py-2 text-[12px] text-[var(--text-secondary)] placeholder-white/25 focus:outline-none focus:border-cyan-500/40"
          />
        </div>

        {fetchLoading && items.length === 0 && (
          <SkeletonWidgetGrid count={3} className="lg:grid-cols-1" />
        )}

        {!fetchLoading && filteredItems.length === 0 && (
          <EmptyState
            icon="shield"
            title={t('pages.councilHitlQueue.empty_title')}
            body={search.trim() ? t('pages.councilHitlQueue.empty_search') : t('pages.councilHitlQueue.empty')}
            cta={search.trim() ? { label: t('pages.councilHitlQueue.clear_search'), onClick: () => setSearch('') } : { label: t('pages.councilHitlQueue.refresh'), onClick: fetchQueue }}
          />
        )}

        {filteredItems.length > 0 && (
          <div className="space-y-4">
            <AnimatePresence>
              {filteredItems.map(item => (
                <HitlItem
                  key={item.id}
                  item={item}
                  onApprove={handleApprove}
                  onReject={handleReject}
                  loading={actionLoading}
                />
              ))}
            </AnimatePresence>
          </div>
        )}
      </div>

      <AnimatePresence>
        {toast && (
          <motion.div
            initial={{ opacity: 0, y: 16 }}
            animate={{ opacity: 1, y: 0 }}
            exit={{ opacity: 0, y: 16 }}
            className={`fixed bottom-6 end-6 px-4 py-3 rounded-2xl border text-[12px] font-mono z-50 ${
              toast.ok
                ? 'bg-green-900/40 border-green-500/30 text-green-300'
                : 'bg-red-900/40 border-red-500/30 text-red-300'
            }`}
          >
            {toast.msg}
          </motion.div>
        )}
      </AnimatePresence>
    </PageShell>
  )
}
