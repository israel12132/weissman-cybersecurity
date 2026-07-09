import { useEffect, useMemo, useState } from 'react';
import { useTranslation } from 'react-i18next'
import { Link, useParams } from 'react-router-dom'
import PageShell from './PageShell'
import ShellScanActions from '../components/engine/ShellScanActions'
import WeissmanListToolbar from '../components/engine/WeissmanListToolbar'
import EmptyState from '../components/ui/EmptyState'
import { useFindingsWorkbench } from '../hooks/useFindingsWorkbench'
import { apiFetch, apiUrl } from '../lib/apiBase'
import { confirmDialog } from '../utils/confirmDialog'
import { useToast } from '../components/ui/Toaster'

function isoNowLocal() {
  const d = new Date()
  d.setMinutes(d.getMinutes() - d.getTimezoneOffset())
  return d.toISOString().slice(0, 16)
}

export default function ClientEngagements() {
  const { t } = useTranslation()
  const { toast } = useToast()
  const { id } = useParams()
  const clientId = useMemo(() => String(id || '').trim(), [id])

  const [client, setClient] = useState(null)
  const [engagements, setEngagements] = useState([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState('')
  const [creating, setCreating] = useState(false)

  const [name, setName] = useState('')
  const [roeMode, setRoeMode] = useState('safe_proofs')
  const [startAt, setStartAt] = useState(isoNowLocal())
  const [endAt, setEndAt] = useState('')
  const [notes, setNotes] = useState('')

  useEffect(() => {
    if (!clientId) return
    loadAll()
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [clientId])

  async function loadAll() {
    setLoading(true)
    setError('')
    try {
      const [clientRes, listRes] = await Promise.all([
        apiFetch(`/api/clients/${clientId}`),
        apiFetch(`/api/clients/${clientId}/engagements`),
      ])

      if (!clientRes.ok) {
        setError(t('pages.clientEngagements.load_client_failed', { status: clientRes.status }))
        setLoading(false)
        return
      }
      const clientData = await clientRes.json().catch(() => null)
      setClient(clientData)

      if (!listRes.ok) {
        const detail = await listRes.text().catch(() => '')
        setError(t('pages.clientEngagements.load_failed', { status: listRes.status, detail }))
        setLoading(false)
        return
      }
      const listData = await listRes.json().catch(() => ({}))
      setEngagements(Array.isArray(listData.engagements) ? listData.engagements : [])
    } catch (e) {
      setError(e?.message || t('pages.clientEngagements.network_error'))
    } finally {
      setLoading(false)
    }
  }

  async function createEngagement() {
    const n = name.trim()
    if (!n) {
      toast.warning(t('pages.clientEngagements.name_required'))
      return
    }
    setCreating(true)
    setError('')
    try {
      const payload = {
        name: n,
        roe_mode: roeMode,
        start_at: startAt ? new Date(startAt).toISOString() : undefined,
        end_at: endAt ? new Date(endAt).toISOString() : undefined,
        notes: notes.trim() || undefined,
      }
      const res = await apiFetch(`/api/clients/${clientId}/engagements`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(payload),
      })
      const data = await res.json().catch(() => ({}))
      if (!res.ok) {
        setError(data?.detail || `Create failed (HTTP ${res.status})`)
        return
      }
      setName('')
      setNotes('')
      setEndAt('')
      await loadAll()
      toast.success(t('pages.clientEngagements.create_success'))
    } catch (e) {
      setError(e?.message || t('pages.clientEngagements.create_failed'))
    } finally {
      setCreating(false)
    }
  }

  async function closeEngagement(engagement) {
    const ok = await confirmDialog({
      title: t('pages.clientEngagements.close_title'),
      message: t('pages.clientEngagements.close_confirm', { name: engagement.name }),
      confirmLabel: t('pages.clientEngagements.close_action'),
      cancelLabel: t('common.cancel'),
      variant: 'warning',
    })
    if (!ok) return
    try {
      const res = await apiFetch(`/api/engagements/${engagement.id}`, {
        method: 'PATCH',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ status: 'closed', end_at: new Date().toISOString() }),
      })
      const data = await res.json().catch(() => ({}))
      if (!res.ok) {
        toast.error(data?.detail || `Close failed (HTTP ${res.status})`)
        return
      }
      await loadAll()
      toast.success(t('pages.clientEngagements.close_success'))
    } catch (e) {
      toast.error(e?.message || t('pages.clientEngagements.close_failed'))
    }
  }

  const listFindings = useMemo(() => engagements.map((e) => ({
    id: e.id,
    severity: e.status === 'active' ? 'medium' : 'info',
    title: e.name || `#${e.id}`,
    type: e.roe_mode || 'engagement',
    description: e.notes || '',
    resource: e.status || '',
  })), [engagements])

  const {
    exportCsv,
    filteredFindings,
    searchQuery,
    setSearchQuery,
  } = useFindingsWorkbench(listFindings, {
    csvPrefix: 'weissman-client-engagements',
    haystackFn: (f) => `${f.title} ${f.type} ${f.description} ${f.resource}`,
  })

  const visibleEngagements = useMemo(() => {
    if (!searchQuery.trim()) return engagements
    const ids = new Set(filteredFindings.map((f) => String(f.id)))
    return engagements.filter((e) => ids.has(String(e.id)))
  }, [engagements, filteredFindings, searchQuery])

  if (loading) {
    return (
      <PageShell title={t('pages.clientEngagements.title')} subtitle={t('pages.clientEngagements.loading_subtitle')}>
        <div className="text-center py-12">
          <div className="inline-block w-8 h-8 border-4 border-purple-500 border-t-transparent rounded-full animate-spin" />
          <p className="mt-4 text-slate-400">{t('pages.clientEngagements.loading')}</p>
        </div>
      </PageShell>
    )
  }

  return (
    <PageShell
      title={client?.name
        ? t('pages.clientEngagements.title_with_client', { name: client.name })
        : t('pages.clientEngagements.title')}
      subtitle={t('pages.clientEngagements.subtitle')}
      actions={(
        <ShellScanActions
          onRefresh={loadAll}
          onExport={exportCsv}
          refreshLoading={loading}
          exportDisabled={!filteredFindings.length}
        />
      )}
    >
      <div className="max-w-5xl mx-auto space-y-6">
        <div className="flex items-center justify-between">
          <Link to={`/clients/${clientId}`} className="text-sm text-slate-400 hover:text-slate-200">
            {t('pages.clientEngagements.back_to_client')}
          </Link>
          <div className="text-xs text-slate-500 font-mono">
            {t('pages.clientEngagements.client_id', { id: clientId })}
          </div>
        </div>

        {error && (
          <div className="p-4 bg-red-900/20 border border-red-500/30 rounded-lg text-red-300">
            {error}
          </div>
        )}

        <div className="p-6 bg-slate-800/40 border border-slate-700 rounded-xl">
          <div className="flex items-center justify-between gap-4">
            <div>
              <h2 className="text-lg font-semibold text-white">{t('pages.clientEngagements.create_heading')}</h2>
              <p className="text-xs text-slate-400 mt-1">{t('pages.clientEngagements.create_body')}</p>
            </div>
            <button
              type="button"
              onClick={createEngagement}
              disabled={creating}
              className="px-4 py-2 bg-purple-600 text-white rounded-lg hover:bg-purple-700 disabled:opacity-50"
            >
              {creating ? t('pages.clientEngagements.creating') : t('pages.clientEngagements.create')}
            </button>
          </div>

          <div className="mt-5 grid grid-cols-1 md:grid-cols-2 gap-4">
            <div>
              <label className="block text-xs text-slate-400 mb-1">{t('pages.clientEngagements.name')}</label>
              <input
                className="w-full px-3 py-2 bg-slate-900/60 border border-slate-700 rounded-lg text-white"
                value={name}
                onChange={(e) => setName(e.target.value)}
                placeholder={t('pages.clientEngagements.name_placeholder')}
              />
            </div>

            <div>
              <label className="block text-xs text-slate-400 mb-1">{t('pages.clientEngagements.roe_mode')}</label>
              <select
                className="w-full px-3 py-2 bg-slate-900/60 border border-slate-700 rounded-lg text-white"
                value={roeMode}
                onChange={(e) => setRoeMode(e.target.value)}
              >
                <option value="safe_proofs">{t('pages.clientEngagements.roe_safe')}</option>
                <option value="weaponized_god_mode">{t('pages.clientEngagements.roe_weaponized')}</option>
              </select>
            </div>

            <div>
              <label className="block text-xs text-slate-400 mb-1">{t('pages.clientEngagements.start')}</label>
              <input
                type="datetime-local"
                className="w-full px-3 py-2 bg-slate-900/60 border border-slate-700 rounded-lg text-white"
                value={startAt}
                onChange={(e) => setStartAt(e.target.value)}
              />
            </div>

            <div>
              <label className="block text-xs text-slate-400 mb-1">{t('pages.clientEngagements.end_optional')}</label>
              <input
                type="datetime-local"
                className="w-full px-3 py-2 bg-slate-900/60 border border-slate-700 rounded-lg text-white"
                value={endAt}
                onChange={(e) => setEndAt(e.target.value)}
              />
            </div>

            <div className="md:col-span-2">
              <label className="block text-xs text-slate-400 mb-1">{t('pages.clientEngagements.notes_optional')}</label>
              <textarea
                className="w-full min-h-24 px-3 py-2 bg-slate-900/60 border border-slate-700 rounded-lg text-white"
                value={notes}
                onChange={(e) => setNotes(e.target.value)}
                placeholder={t('pages.clientEngagements.notes_placeholder')}
              />
            </div>
          </div>
        </div>

        <div className="p-6 bg-slate-900/30 border border-slate-800 rounded-xl">
          <div className="flex items-center justify-between">
            <h2 className="text-lg font-semibold text-white">{t('pages.clientEngagements.history_heading')}</h2>
            <span className="text-xs text-slate-500">{t('pages.clientEngagements.total', { count: engagements.length })}</span>
          </div>

          {engagements.length === 0 ? (
            <div className="text-center py-10 text-slate-500">
              {t('pages.clientEngagements.empty')}
            </div>
          ) : (
            <>
            <WeissmanListToolbar
              className="mt-4"
              searchQuery={searchQuery}
              onSearchChange={setSearchQuery}
              resultCount={visibleEngagements.length}
              totalCount={engagements.length}
            />
            {visibleEngagements.length === 0 ? (
              <EmptyState
                icon="search"
                title={t('weissmanFindings.filtered_title')}
                body={t('weissmanFindings.filtered_body')}
                compact
              />
            ) : (
            <div className="mt-4 space-y-3">
              {visibleEngagements.map((e) => (
                <div key={e.id} className="p-4 border border-slate-800 rounded-lg bg-[var(--bg-1)]">
                  <div className="flex items-start justify-between gap-4">
                    <div className="min-w-0">
                      <div className="text-white font-medium truncate">{e.name}</div>
                      <div className="mt-1 text-xs text-slate-400 font-mono">
                        {e.status} · {e.roe_mode} · {e.start_at?.slice(0, 19).replace('T', ' ')}
                        {e.end_at ? ` → ${String(e.end_at).slice(0, 19).replace('T', ' ')}` : ''}
                      </div>
                    </div>
                    <div className="flex items-center gap-2 shrink-0">
                      <a
                        href={apiUrl(`/api/engagements/${e.id}`)}
                        className="px-3 py-1 text-xs border border-slate-700 text-slate-300 rounded hover:bg-slate-800"
                        target="_blank"
                        rel="noopener noreferrer"
                        title="Open engagement JSON from API"
                      >
                        {t('pages.clientEngagements.api')}
                      </a>
                      {e.status !== 'closed' && (
                        <button
                          type="button"
                          onClick={() => closeEngagement(e)}
                          className="px-3 py-1 text-xs border border-red-500/40 text-red-300 rounded hover:bg-red-900/20"
                        >
                          {t('pages.clientEngagements.close')}
                        </button>
                      )}
                    </div>
                  </div>
                </div>
              ))}
            </div>
            )}
            </>
          )}
        </div>
      </div>
    </PageShell>
  )
}

