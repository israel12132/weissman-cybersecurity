import React, { useCallback, useEffect, useState } from 'react'
import { useTranslation } from 'react-i18next'
import PageShell from './PageShell'
import { apiFetch } from '../lib/apiBase'

function approvalsHave(req) {
  return Number(!!req.first_approved_by_user_id) + Number(!!req.second_approved_by_user_id)
}

export default function RoeApprovals() {
  const { t } = useTranslation()
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState('')
  const [requests, setRequests] = useState([])
  const [actionId, setActionId] = useState(null)

  const load = useCallback(async () => {
    setLoading(true)
    setError('')
    try {
      const r = await apiFetch('/api/roe/override-requests?status=pending')
      if (!r.ok) {
        const detail = await r.text().catch(() => '')
        setError(t('pages.roeApprovals.load_failed', { status: r.status, detail }))
        setRequests([])
        return
      }
      const data = await r.json().catch(() => ({}))
      setRequests(Array.isArray(data.requests) ? data.requests : [])
    } catch (e) {
      setError(e?.message || t('pages.roeApprovals.network_error'))
      setRequests([])
    } finally {
      setLoading(false)
    }
  }, [t])

  useEffect(() => {
    load()
  }, [load])

  async function approve(req) {
    setActionId(req.id)
    try {
      const r = await apiFetch(`/api/roe/override-requests/${req.id}/approve`, { method: 'POST' })
      const data = await r.json().catch(() => ({}))
      if (!r.ok) {
        alert(data?.detail || t('pages.roeApprovals.approve_failed', { status: r.status }))
        return
      }
      await load()
    } finally {
      setActionId(null)
    }
  }

  async function reject(req) {
    const reason = prompt(t('pages.roeApprovals.reject_prompt'), '')
    if (reason === null) return
    setActionId(req.id)
    try {
      const r = await apiFetch(`/api/roe/override-requests/${req.id}/reject`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ reason }),
      })
      const data = await r.json().catch(() => ({}))
      if (!r.ok) {
        alert(data?.detail || t('pages.roeApprovals.reject_failed', { status: r.status }))
        return
      }
      await load()
    } finally {
      setActionId(null)
    }
  }

  return (
    <PageShell
      title={t('pages.roeApprovals.title')}
      subtitle={t('pages.roeApprovals.subtitle')}
    >
      <div className="max-w-5xl mx-auto space-y-6">
        {error && (
          <div className="p-4 bg-red-900/20 border border-red-500/30 rounded-lg text-red-300">
            {error}
          </div>
        )}

        <div className="flex items-center justify-between">
          <div className="text-xs text-slate-500 font-mono">
            {t('pages.roeApprovals.pending', { count: requests.length })}
          </div>
          <button
            type="button"
            onClick={load}
            className="px-3 py-1.5 text-xs border border-slate-700 text-slate-300 rounded hover:bg-slate-800"
            disabled={loading}
          >
            {t('pages.roeApprovals.refresh')}
          </button>
        </div>

        {loading ? (
          <div className="text-center py-12 text-slate-400">
            <div className="inline-block w-8 h-8 border-4 border-purple-500 border-t-transparent rounded-full animate-spin" />
            <p className="mt-4">{t('pages.roeApprovals.loading')}</p>
          </div>
        ) : requests.length === 0 ? (
          <div className="text-center py-12 text-slate-500 border border-dashed border-slate-700 rounded-xl">
            {t('pages.roeApprovals.empty')}
          </div>
        ) : (
          <div className="space-y-3">
            {requests.map((req) => (
              <div key={req.id} className="p-5 rounded-2xl bg-black/40 border border-white/10">
                <div className="flex items-start justify-between gap-4 flex-wrap">
                  <div className="min-w-0">
                    <div className="flex items-center gap-2 flex-wrap">
                      <span className="text-[11px] font-mono text-white/30">#{req.id}</span>
                      <span className="text-[10px] font-mono uppercase px-2 py-0.5 rounded border border-amber-400/30 text-amber-300 bg-amber-900/10">
                        {req.status}
                      </span>
                      <span className="text-[11px] font-mono text-white/50">
                        {t('pages.roeApprovals.approvals_count', { count: approvalsHave(req) })}
                      </span>
                    </div>
                    <div className="mt-2 text-sm font-medium text-white truncate">
                      {t('pages.roeApprovals.client', {
                        id: req.client_id,
                        name: req.client_name ? ` — ${req.client_name}` : '',
                      })}
                    </div>
                    <div className="mt-1 text-[11px] font-mono text-white/35">
                      {t('pages.roeApprovals.desired', {
                        mode: req.desired_roe_mode,
                        expires: req.expires_at ? new Date(req.expires_at).toLocaleString() : '—',
                      })}
                    </div>
                    {req.justification && (
                      <div className="mt-2 text-[11px] text-white/55 whitespace-pre-wrap">
                        {req.justification}
                      </div>
                    )}
                  </div>

                  <div className="flex items-center gap-2 shrink-0">
                    <button
                      type="button"
                      onClick={() => approve(req)}
                      disabled={actionId === req.id}
                      className="px-3 py-1.5 text-xs border border-emerald-500/40 text-emerald-200 rounded hover:bg-emerald-900/20 disabled:opacity-50"
                    >
                      {t('pages.roeApprovals.approve')}
                    </button>
                    <button
                      type="button"
                      onClick={() => reject(req)}
                      disabled={actionId === req.id}
                      className="px-3 py-1.5 text-xs border border-rose-500/40 text-rose-200 rounded hover:bg-rose-900/20 disabled:opacity-50"
                    >
                      {t('pages.roeApprovals.reject')}
                    </button>
                  </div>
                </div>
              </div>
            ))}
          </div>
        )}
      </div>
    </PageShell>
  )
}
