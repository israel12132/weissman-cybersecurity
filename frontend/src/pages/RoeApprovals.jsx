import { useCallback, useEffect, useMemo, useState } from 'react'
import { useTranslation } from 'react-i18next'
import PageShell from './PageShell'
import ShellScanActions from '../components/engine/ShellScanActions'
import WeissmanFindingsPanel from '../components/engine/WeissmanFindingsPanel'
import { useFindingsWorkbench } from '../hooks/useFindingsWorkbench'
import { SkeletonWidgetGrid } from '../components/ui/Skeleton'
import { apiFetch } from '../utils/apiFetch'
import { promptDialog } from '../utils/confirmDialog'
import { useToast } from '../components/ui/Toaster'
import Button from '../components/ui/Button'

function approvalsHave(req) {
  return Number(!!req.first_approved_by_user_id) + Number(!!req.second_approved_by_user_id)
}

export default function RoeApprovals() {
  const { t } = useTranslation()
  const { toast } = useToast()
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState('')
  const [requests, setRequests] = useState([])
  const [actionId, setActionId] = useState(null)

  const load = useCallback(async () => {
    setLoading(true)
    setError('')
    try {
      const data = await apiFetch('/api/roe/override-requests?status=pending')
      setRequests(Array.isArray(data.requests) ? data.requests : [])
    } catch (e) {
      if (e?.status) {
        const detail = e.response ? await e.response.text().catch(() => '') : ''
        setError(t('pages.roeApprovals.load_failed', { status: e.status, detail }))
      } else {
        setError(e?.message || t('pages.roeApprovals.network_error'))
      }
      setRequests([])
    } finally {
      setLoading(false)
    }
  }, [t])

  useEffect(() => {
    load()
  }, [load])

  const listFindings = useMemo(() => requests.map((req) => ({
    id: req.id,
    severity: req.status === 'pending' ? 'medium' : 'info',
    title: `#${req.id} · ${req.client_name || `Client ${req.client_id}`}`,
    type: req.desired_roe_mode || 'roe_override',
    description: [req.justification, req.expires_at ? `Expires: ${new Date(req.expires_at).toLocaleString()}` : ''].filter(Boolean).join(' · '),
    resource: String(req.client_id),
  })), [requests])

  const {
    filteredFindings,
    counts,
    searchQuery,
    setSearchQuery,
    severityFilter,
    setSeverityFilter,
    exportCsv,
    total,
  } = useFindingsWorkbench(listFindings, {
    csvPrefix: 'roe-approvals',
    haystackFn: (f) => `${f.title} ${f.type} ${f.description} ${f.resource}`,
  })

  async function approve(req) {
    setActionId(req.id)
    try {
      await apiFetch(`/api/roe/override-requests/${req.id}/approve`, { method: 'POST' })
      await load()
      toast.success(t('pages.roeApprovals.approve_success'))
    } catch (e) {
      const b = e?.response ? await e.response.json().catch(() => ({})) : {}
      toast.error(b?.detail || t('pages.roeApprovals.approve_failed', { status: e?.status }))
    } finally {
      setActionId(null)
    }
  }

  async function reject(req) {
    const reason = await promptDialog({
      title: t('pages.roeApprovals.reject_title'),
      message: t('pages.roeApprovals.reject_prompt'),
      label: t('pages.roeApprovals.reject_reason_label'),
      placeholder: t('pages.roeApprovals.reject_reason_placeholder'),
      confirmLabel: t('pages.roeApprovals.reject_action'),
      cancelLabel: t('common.cancel'),
      multiline: true,
    })
    if (reason === null) return
    setActionId(req.id)
    try {
      await apiFetch(`/api/roe/override-requests/${req.id}/reject`, {
        method: 'POST',
        body: { reason },
      })
      await load()
      toast.success(t('pages.roeApprovals.reject_success'))
    } catch (e) {
      const b = e?.response ? await e.response.json().catch(() => ({})) : {}
      toast.error(b?.detail || t('pages.roeApprovals.reject_failed', { status: e?.status }))
    } finally {
      setActionId(null)
    }
  }

  return (
    <PageShell
      title={t('pages.roeApprovals.title')}
      subtitle={t('pages.roeApprovals.subtitle')}
      actions={(
        <ShellScanActions
          onRefresh={load}
          onExport={exportCsv}
          refreshLoading={loading}
          exportDisabled={!filteredFindings.length}
        />
      )}
    >
      <div className="max-w-5xl mx-auto space-y-6">
        {error && (
          <div className="p-4 bg-red-900/20 border border-red-500/30 rounded-lg text-red-300">
            {error}
          </div>
        )}

        <div className="text-xs text-[var(--text-muted)] font-mono">
          {t('pages.roeApprovals.pending', { count: requests.length })}
        </div>

        {loading && !requests.length ? (
          <div className="rounded-2xl bg-[var(--bg-2)] border border-[var(--border-default)] p-6">
            <SkeletonWidgetGrid count={3} />
          </div>
        ) : (
          <WeissmanFindingsPanel
            findings={listFindings}
            filteredFindings={filteredFindings}
            counts={counts}
            total={total}
            searchQuery={searchQuery}
            onSearchChange={setSearchQuery}
            severityFilter={severityFilter}
            onSeverityChange={setSeverityFilter}
            loading={loading && !listFindings.length}
            accent="#a855f7"
            emptyTitle={t('pages.roeApprovals.empty')}
            emptyBody={t('pages.roeApprovals.empty')}
            renderFinding={(f) => {
              const req = requests.find((r) => r.id === f.id)
              if (!req) return null
              return (
                <div key={req.id} className="rounded-xl border border-[var(--border-default)] bg-[var(--table-surface)] p-4 space-y-3">
                  <div className="flex items-start justify-between gap-4 flex-wrap">
                    <div className="min-w-0">
                      <div className="flex items-center gap-2 flex-wrap">
                        <span className="text-[11px] font-mono text-[var(--text-disabled)]">#{req.id}</span>
                        <span className="text-[10px] font-mono uppercase px-2 py-0.5 rounded border border-amber-400/30 text-amber-300 bg-amber-900/10">
                          {req.status}
                        </span>
                        <span className="text-[11px] font-mono text-[var(--text-tertiary)]">
                          {t('pages.roeApprovals.approvals_count', { count: approvalsHave(req) })}
                        </span>
                      </div>
                      <p className="mt-2 text-sm font-medium text-white">{f.title}</p>
                      <p className="mt-1 text-[11px] font-mono text-[var(--text-muted)]">{f.description}</p>
                    </div>
                    <div className="flex items-center gap-2 shrink-0">
                      <Button variant="unstyled"
                        type="button"
                        onClick={() => approve(req)}
                        disabled={actionId === req.id}
                        className="px-3 py-1.5 text-xs border border-emerald-500/40 text-emerald-200 rounded hover:bg-emerald-900/20 disabled:opacity-50"
                      >
                        {t('pages.roeApprovals.approve')}
                      </Button>
                      <Button variant="unstyled"
                        type="button"
                        onClick={() => reject(req)}
                        disabled={actionId === req.id}
                        className="px-3 py-1.5 text-xs border border-rose-500/40 text-rose-200 rounded hover:bg-rose-900/20 disabled:opacity-50"
                      >
                        {t('pages.roeApprovals.reject')}
                      </Button>
                    </div>
                  </div>
                </div>
              )
            }}
          />
        )}
      </div>
    </PageShell>
  )
}
