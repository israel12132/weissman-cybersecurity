import React, { useCallback, useEffect, useState } from 'react'
import { useTranslation } from 'react-i18next'
import { apiFetch } from '../lib/apiBase'
import EmptyState from '../components/ui/EmptyState'
import { SkeletonTable } from '../components/ui/Skeleton'

function fmtTime(iso) {
  if (!iso) return '—'
  try {
    return new Date(iso).toLocaleString()
  } catch {
    return String(iso)
  }
}

function ActionBadge({ action }) {
  const a = (action || '').toLowerCase()
  let color = 'border-white/15 text-white/70 bg-white/5'
  if (a.includes('login') || a.includes('mfa')) color = 'border-cyan-500/40 text-cyan-200 bg-cyan-500/10'
  if (a.includes('denied') || a.includes('reject') || a.includes('failed')) color = 'border-rose-500/40 text-rose-200 bg-rose-500/10'
  if (a.includes('created') || a.includes('updated')) color = 'border-emerald-500/40 text-emerald-200 bg-emerald-500/10'
  if (a.includes('deleted') || a.includes('removed')) color = 'border-amber-500/40 text-amber-200 bg-amber-500/10'
  if (a.includes('scan')) color = 'border-violet-500/40 text-violet-200 bg-violet-500/10'
  return (
    <span className={`text-[10px] font-mono px-2 py-0.5 rounded border ${color}`}>{action || '—'}</span>
  )
}

export default function AuditLog() {
  const { t } = useTranslation()
  const [entries, setEntries] = useState([])
  const [total, setTotal] = useState(0)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState(null)
  const [filter, setFilter] = useState('')
  const [actor, setActor] = useState('')
  const [offset, setOffset] = useState(0)
  const limit = 100

  const load = useCallback(async () => {
    setLoading(true)
    setError(null)
    const qs = new URLSearchParams({ limit: String(limit), offset: String(offset) })
    if (filter) qs.set('action', filter)
    if (actor) qs.set('actor', actor)
    try {
      const r = await apiFetch(`/api/audit-logs?${qs.toString()}`)
      if (!r.ok) throw new Error(`HTTP ${r.status}`)
      const d = await r.json()
      const list = Array.isArray(d) ? d : Array.isArray(d?.entries) ? d.entries : []
      setEntries(list)
      setTotal(Number(d?.total ?? list.length))
    } catch (e) {
      setError(e.message || 'Failed to load audit log')
    } finally {
      setLoading(false)
    }
  }, [filter, actor, offset])

  useEffect(() => { load() }, [load])

  return (
    <div
      className="min-h-[100dvh] text-slate-100 p-6"
      style={{ background: 'radial-gradient(ellipse 100% 70% at 50% 0%, #0f172a 0%, #020617 60%, #000 100%)' }}
    >
      <header className="max-w-6xl mx-auto mb-6 flex items-end justify-between gap-3 flex-wrap">
        <div>
          <h1 className="text-2xl font-bold">{t('nav.audit_log', { defaultValue: 'Audit log' })}</h1>
          <p className="text-sm text-white/55 mt-1">
            Every authenticated action recorded by the platform. Tenant-scoped, immutable.
          </p>
        </div>
        <div className="text-[11px] font-mono text-white/40">
          {entries.length} shown · {total} total
        </div>
      </header>

      <section className="max-w-6xl mx-auto rounded-2xl bg-black/40 border border-white/10 backdrop-blur-md p-5 mb-4">
        <div className="grid grid-cols-1 sm:grid-cols-[1fr_1fr_auto] gap-3">
          <input
            type="search"
            placeholder="Filter by action (login, scan_initiated, client_created, …)"
            value={filter}
            onChange={(e) => { setFilter(e.target.value); setOffset(0) }}
            className="bg-black/50 border border-white/10 rounded-lg px-3 py-2 text-sm font-mono text-white/85 placeholder-white/30 focus:outline-none focus:border-cyan-500/40"
          />
          <input
            type="search"
            placeholder="Filter by actor email"
            value={actor}
            onChange={(e) => { setActor(e.target.value); setOffset(0) }}
            className="bg-black/50 border border-white/10 rounded-lg px-3 py-2 text-sm font-mono text-white/85 placeholder-white/30 focus:outline-none focus:border-cyan-500/40"
          />
          <button
            type="button"
            onClick={load}
            className="px-3 py-2 rounded-lg text-sm font-mono border border-white/10 text-white/55 hover:text-white hover:border-white/30"
          >
            {t('common.refresh')}
          </button>
        </div>
      </section>

      <section className="max-w-6xl mx-auto rounded-2xl bg-black/40 border border-white/10 backdrop-blur-md p-5">
        {error && (
          <div className="text-sm text-rose-300 mb-3 font-mono">{error}</div>
        )}
        {loading ? (
          <SkeletonTable rows={10} cols={5} />
        ) : entries.length === 0 ? (
          <EmptyState
            icon="📋"
            title="No audit entries"
            body="No matching audit entries. Try a different filter, or perform an action (login, create client) and refresh."
          />
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-[12px] font-mono">
              <thead>
                <tr className="text-left text-white/45 border-b border-white/10">
                  <th className="py-2 pe-3 w-44">When</th>
                  <th className="py-2 pe-3 w-40">Action</th>
                  <th className="py-2 pe-3">Actor</th>
                  <th className="py-2 pe-3">Details</th>
                  <th className="py-2 pe-3 w-32">IP</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-white/5">
                {entries.map((e) => (
                  <tr key={e.id} className="hover:bg-white/[0.02] align-top">
                    <td className="py-2 pe-3 text-white/65">{fmtTime(e.created_at)}</td>
                    <td className="py-2 pe-3"><ActionBadge action={e.action} /></td>
                    <td className="py-2 pe-3 text-cyan-300/80 truncate max-w-[16rem]" title={e.actor_email}>
                      {e.actor_email || `user#${e.user_id || '—'}`}
                    </td>
                    <td className="py-2 pe-3 text-white/55 break-words">
                      {e.details ? e.details.slice(0, 240) : '—'}
                    </td>
                    <td className="py-2 pe-3 text-white/40">{e.client_ip || '—'}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}

        {total > limit && (
          <div className="flex justify-between items-center mt-4 text-[11px] font-mono">
            <button
              type="button"
              disabled={offset <= 0}
              onClick={() => setOffset((o) => Math.max(0, o - limit))}
              className="px-3 py-1.5 rounded border border-white/10 text-white/55 disabled:opacity-30"
            >
              ← Prev
            </button>
            <span className="text-white/45">
              {offset + 1}–{Math.min(offset + entries.length, total)} / {total}
            </span>
            <button
              type="button"
              disabled={offset + entries.length >= total}
              onClick={() => setOffset((o) => o + limit)}
              className="px-3 py-1.5 rounded border border-white/10 text-white/55 disabled:opacity-30"
            >
              Next →
            </button>
          </div>
        )}
      </section>
    </div>
  )
}
