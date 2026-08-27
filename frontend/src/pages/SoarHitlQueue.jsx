import { useState, useEffect, useCallback, useMemo } from 'react'
import { Link } from 'react-router'
import { useTranslation } from 'react-i18next'
import { motion, AnimatePresence } from 'framer-motion'
import { downloadCsv } from '../lib/exportFindingsCsv'
import { Search, ShieldAlert } from 'lucide-react'
import PageShell from './PageShell'
import ShellScanActions from '../components/engine/ShellScanActions'
import { useFindingsWorkbench } from '../hooks/useFindingsWorkbench'
import EvidenceNotice from '../components/ui/EvidenceNotice'
import EmptyState from '../components/ui/EmptyState'
import { SkeletonWidgetGrid } from '../components/ui/Skeleton'
import { apiFetch } from '../utils/apiFetch'
import Button from '../components/ui/Button'
import DualControlGate from '../components/ui/DualControlGate'
import {
  dualControlHeaders,
  loadDestructiveConfirmToken,
  loadDualApproveToken,
  persistDualControlTokens,
} from '../utils/destructiveConfirm'

const STATUS_TABS = ['pending_hitl', 'failed', 'resolved', 'all']

const STATUS_COLORS = {
  pending_hitl: 'text-amber-400 border-amber-400/30 bg-amber-900/10',
  failed: 'text-rose-400 border-rose-400/30 bg-rose-900/10',
  resolved: 'text-emerald-400 border-emerald-400/30 bg-emerald-900/10',
  executing: 'text-cyan-400 border-cyan-400/30 bg-cyan-900/10',
  verifying: 'text-violet-300 border-violet-400/30 bg-violet-900/10',
}

function exportQueueCsv(items) {
  const header = ['id', 'status', 'action_kind', 'target_id', 'crown_jewel', 'created_at', 'result_detail']
  const rows = items.map((item) => [
    item.id,
    item.status,
    item.action_kind,
    item.target_id,
    item.crown_jewel_touched ? 'yes' : 'no',
    item.created_at,
    item.result_detail,
  ])
  downloadCsv(rows, header, 'weissman-soar-hitl')
}

function StatusBadge({ status }) {
  const { t } = useTranslation()
  const cls = STATUS_COLORS[status] ?? 'text-[var(--text-muted)] border-[var(--border-default)]'
  return (
    <span className={`text-[10px] font-mono uppercase px-2 py-0.5 rounded border ${cls}`}>
      {t(`pages.soarHitlQueue.status_${status}`, { defaultValue: status?.replace(/_/g, ' ') })}
    </span>
  )
}

function HitlItem({ item, onApprove, onDeny, loading }) {
  const { t } = useTranslation()
  const [expanded, setExpanded] = useState(false)
  const [note, setNote] = useState('')
  const isPending = item.status === 'pending_hitl'

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
            <span className="text-[11px] font-mono text-[var(--text-disabled)]">{String(item.id || '').slice(0, 8)}</span>
            <StatusBadge status={item.status} />
            {item.crown_jewel_touched && (
              <span className="text-[10px] font-mono uppercase px-2 py-0.5 rounded border border-rose-500/40 bg-rose-900/20 text-rose-200">
                {t('pages.soarHitlQueue.crown_jewel')}
              </span>
            )}
            <span className="text-[11px] font-semibold uppercase text-cyan-200/80">
              {item.action_kind}
            </span>
          </div>
          <p className="text-sm font-medium text-white truncate max-w-lg">{item.target_id || '—'}</p>
          <p className="text-[10px] font-mono text-[var(--text-disabled)]">
            {item.created_at ? new Date(item.created_at).toLocaleString() : ''}
            {item.client_id ? t('pages.soarHitlQueue.client_suffix', { id: item.client_id }) : ''}
          </p>
        </div>
        <Button
          variant="unstyled"
          type="button"
          onClick={() => setExpanded((v) => !v)}
          className="shrink-0 text-[11px] font-mono text-[var(--text-muted)] hover:text-[var(--text-secondary)] transition-colors px-3 py-1.5 rounded-lg border border-[var(--border-default)] hover:border-[var(--border-strong)]"
        >
          {expanded ? t('pages.soarHitlQueue.collapse') : t('pages.soarHitlQueue.details')}
        </Button>
      </div>

      <AnimatePresence>
        {expanded && (
          <motion.div
            initial={{ opacity: 0, height: 0 }}
            animate={{ opacity: 1, height: 'auto' }}
            exit={{ opacity: 0, height: 0 }}
            className="overflow-hidden space-y-3"
          >
            {item.result_detail && (
              <p className="text-[12px] text-[var(--text-tertiary)] leading-relaxed">{item.result_detail}</p>
            )}
            <pre className="rounded-xl bg-[var(--row-hover-bg)] border border-[var(--border-default)] p-3 text-[11px] font-mono text-cyan-300/70 whitespace-pre-wrap break-words max-h-40 overflow-y-auto">
              {JSON.stringify(item.blast_radius || {}, null, 2)}
            </pre>
          </motion.div>
        )}
      </AnimatePresence>

      {isPending && (
        <div className="flex flex-col sm:flex-row gap-3 pt-1">
          <input
            type="text"
            placeholder={t('pages.soarHitlQueue.deny_reason')}
            value={note}
            onChange={(e) => setNote(e.target.value)}
            className="flex-1 rounded-xl bg-[var(--row-hover-bg)] border border-[var(--border-default)] px-3 py-1.5 text-[12px] text-[var(--text-secondary)] placeholder-white/20 focus:outline-none focus:border-cyan-500/40"
          />
          <Button
            variant="unstyled"
            type="button"
            disabled={loading}
            onClick={() => onApprove(item.id)}
            className="px-4 py-1.5 rounded-xl text-[12px] font-semibold font-mono uppercase border border-green-500/40 text-green-400 hover:bg-green-900/20 disabled:opacity-40 disabled:cursor-not-allowed transition-all"
          >
            {t('pages.soarHitlQueue.approve')}
          </Button>
          <Button
            variant="unstyled"
            type="button"
            disabled={loading}
            onClick={() => onDeny(item.id, note)}
            className="px-4 py-1.5 rounded-xl text-[12px] font-semibold font-mono uppercase border border-rose-500/40 text-rose-400 hover:bg-rose-900/20 disabled:opacity-40 disabled:cursor-not-allowed transition-all"
          >
            {t('pages.soarHitlQueue.deny')}
          </Button>
        </div>
      )}
    </motion.div>
  )
}

export default function SoarHitlQueue() {
  const { t } = useTranslation()
  const [items, setItems] = useState([])
  const [pendingCount, setPendingCount] = useState(0)
  const [fetchLoading, setFetchLoading] = useState(true)
  const [actionLoading, setActionLoading] = useState(false)
  const [activeTab, setActiveTab] = useState('pending_hitl')
  const [search, setSearch] = useState('')
  const [toast, setToast] = useState(null)
  const [confirm, setConfirm] = useState(() => loadDestructiveConfirmToken())
  const [dual, setDual] = useState(() => loadDualApproveToken())
  const [remember, setRemember] = useState(true)

  const showToast = useCallback((msg, ok = true) => {
    setToast({ msg, ok })
    setTimeout(() => setToast(null), 4000)
  }, [])

  const fetchQueue = useCallback(async () => {
    setFetchLoading(true)
    try {
      const data = await apiFetch(`/api/soar/executions?status=${encodeURIComponent(activeTab)}`)
      setItems(Array.isArray(data.items) ? data.items : [])
      setPendingCount(Number(data.pending_count) || 0)
    } catch (e) {
      showToast(t('pages.soarHitlQueue.load_failed', { message: e.message }), false)
    } finally {
      setFetchLoading(false)
    }
  }, [activeTab, showToast, t])

  useEffect(() => {
    fetchQueue()
  }, [fetchQueue])

  const headersForAction = useCallback(() => {
    persistDualControlTokens(confirm, dual, remember)
    return dualControlHeaders(confirm, dual)
  }, [confirm, dual, remember])

  const handleApprove = useCallback(async (id) => {
    setActionLoading(true)
    try {
      await apiFetch(`/api/soar/executions/${encodeURIComponent(id)}/hitl/approve`, {
        method: 'POST',
        headers: headersForAction(),
      })
      showToast(t('pages.soarHitlQueue.approved_toast'))
      await fetchQueue()
    } catch (e) {
      showToast(t('pages.soarHitlQueue.approval_failed', { message: e.message }), false)
    } finally {
      setActionLoading(false)
    }
  }, [fetchQueue, headersForAction, showToast, t])

  const handleDeny = useCallback(async (id, note) => {
    setActionLoading(true)
    try {
      await apiFetch(`/api/soar/executions/${encodeURIComponent(id)}/hitl/deny`, {
        method: 'POST',
        headers: headersForAction(),
        body: { reason: note || '' },
      })
      showToast(t('pages.soarHitlQueue.denied_toast'))
      await fetchQueue()
    } catch (e) {
      showToast(t('pages.soarHitlQueue.deny_failed', { message: e.message }), false)
    } finally {
      setActionLoading(false)
    }
  }, [fetchQueue, headersForAction, showToast, t])

  const filteredItems = useMemo(() => {
    const q = search.trim().toLowerCase()
    if (!q) return items
    return items.filter((item) => {
      const hay = [item.id, item.target_id, item.action_kind, item.status, item.result_detail]
        .filter(Boolean)
        .join(' ')
        .toLowerCase()
      return hay.includes(q)
    })
  }, [items, search])

  const listFindings = useMemo(() => filteredItems.map((item) => ({
    id: item.id,
    severity: item.crown_jewel_touched ? 'critical' : 'high',
    title: item.target_id || String(item.id),
    type: item.status || 'hitl',
    description: item.action_kind || '',
    resource: String(item.client_id ?? ''),
  })), [filteredItems])

  const { filteredFindings } = useFindingsWorkbench(listFindings, {
    csvPrefix: 'weissman-soar-hitl',
    haystackFn: (f) => `${f.title} ${f.type} ${f.description} ${f.resource}`,
  })

  const headerActions = (
    <div className="flex items-center gap-2 flex-wrap">
      <Link
        to="/playbooks"
        className="text-[11px] font-mono px-2 py-1 rounded border border-violet-500/40 text-violet-300 hover:bg-violet-500/10"
      >
        {t('nav.playbooks')}
      </Link>
      <ShellScanActions
        onRefresh={fetchQueue}
        onExport={() => exportQueueCsv(filteredItems)}
        refreshLoading={fetchLoading}
        exportDisabled={!filteredFindings.length}
      />
    </div>
  )

  return (
    <PageShell
      title={t('pages.soarHitlQueue.title')}
      subtitle={t('pages.soarHitlQueue.subtitle')}
      icon={<ShieldAlert className="w-5 h-5 text-rose-400" strokeWidth={1.75} />}
      badge={pendingCount > 0 ? t('pages.soarHitlQueue.pending_badge', { count: pendingCount }) : undefined}
      badgeColor="#fb7185"
      actions={headerActions}
      maxWidth="max-w-4xl"
    >
      <div className="space-y-6">
        <EvidenceNotice>{t('pages.soarHitlQueue.evidence_notice')}</EvidenceNotice>

        <div className="rounded-2xl bg-rose-900/10 border border-rose-500/20 px-4 py-3 flex items-start gap-3">
          <span className="text-rose-400 mt-0.5">🔒</span>
          <div>
            <p className="text-[12px] font-semibold text-rose-200">{t('pages.soarHitlQueue.safety_title')}</p>
            <p className="text-[11px] text-[var(--text-muted)] mt-0.5">
              {t('pages.soarHitlQueue.safety_body')}
            </p>
          </div>
        </div>

        <DualControlGate
          confirm={confirm}
          dual={dual}
          onConfirmChange={setConfirm}
          onDualChange={setDual}
          remember={remember}
          onRememberChange={setRemember}
        />

        <div className="flex gap-1 flex-wrap items-center">
          {STATUS_TABS.map((tab) => (
            <Button
              variant="unstyled"
              key={tab}
              type="button"
              onClick={() => setActiveTab(tab)}
              className={`px-3 py-1.5 rounded-xl text-[11px] font-mono uppercase border transition-all ${
                activeTab === tab
                  ? 'bg-rose-900/20 border-rose-500/40 text-rose-200'
                  : 'border-[var(--border-default)] text-[var(--text-muted)] hover:border-[var(--border-strong)] hover:text-[var(--text-tertiary)]'
              }`}
            >
              {t(`pages.soarHitlQueue.tab_${tab}`)}
            </Button>
          ))}
        </div>

        <div className="relative">
          <Search className="absolute start-3 top-1/2 -translate-y-1/2 w-4 h-4 text-[var(--text-disabled)] pointer-events-none" />
          <input
            type="search"
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            placeholder={t('pages.soarHitlQueue.search_placeholder')}
            aria-label={t('pages.soarHitlQueue.search_placeholder')}
            className="w-full rounded-xl bg-[var(--row-hover-bg)] border border-[var(--border-default)] ps-10 pe-3 py-2 text-[12px] text-[var(--text-secondary)] placeholder-white/25 focus:outline-none focus:border-cyan-500/40"
          />
        </div>

        {fetchLoading && items.length === 0 && (
          <SkeletonWidgetGrid count={3} className="lg:grid-cols-1" />
        )}

        {!fetchLoading && filteredItems.length === 0 && (
          <EmptyState
            icon="shield"
            title={t('pages.soarHitlQueue.empty_title')}
            body={search.trim() ? t('pages.soarHitlQueue.empty_search') : t('pages.soarHitlQueue.empty')}
            cta={search.trim()
              ? { label: t('pages.soarHitlQueue.clear_search'), onClick: () => setSearch('') }
              : { label: t('pages.soarHitlQueue.refresh'), onClick: fetchQueue }}
          />
        )}

        {filteredItems.length > 0 && (
          <div className="space-y-4">
            <AnimatePresence>
              {filteredItems.map((item) => (
                <HitlItem
                  key={item.id}
                  item={item}
                  onApprove={handleApprove}
                  onDeny={handleDeny}
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
