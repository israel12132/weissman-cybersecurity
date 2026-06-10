import { useEffect, useMemo, useState } from 'react'
import { Link, useParams } from 'react-router-dom'
import PageShell from './PageShell'
import { apiFetch } from '../lib/apiBase'

function isoNowLocal() {
  const d = new Date()
  d.setMinutes(d.getMinutes() - d.getTimezoneOffset())
  return d.toISOString().slice(0, 16)
}

export default function ClientEngagements() {
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
        setError(`Failed to load client (HTTP ${clientRes.status})`)
        setLoading(false)
        return
      }
      const clientData = await clientRes.json().catch(() => null)
      setClient(clientData)

      if (!listRes.ok) {
        const t = await listRes.text().catch(() => '')
        setError(`Failed to load engagements (HTTP ${listRes.status}) ${t}`)
        setLoading(false)
        return
      }
      const listData = await listRes.json().catch(() => ({}))
      setEngagements(Array.isArray(listData.engagements) ? listData.engagements : [])
    } catch (e) {
      setError(e?.message || 'Network error')
    } finally {
      setLoading(false)
    }
  }

  async function createEngagement() {
    const n = name.trim()
    if (!n) {
      alert('Engagement name is required.')
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
    } catch (e) {
      setError(e?.message || 'Create failed')
    } finally {
      setCreating(false)
    }
  }

  async function closeEngagement(engagement) {
    if (!confirm(`Close engagement "${engagement.name}"?`)) return
    try {
      const res = await apiFetch(`/api/engagements/${engagement.id}`, {
        method: 'PATCH',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ status: 'closed', end_at: new Date().toISOString() }),
      })
      const data = await res.json().catch(() => ({}))
      if (!res.ok) {
        alert(data?.detail || `Close failed (HTTP ${res.status})`)
        return
      }
      await loadAll()
    } catch (e) {
      alert(e?.message || 'Close failed')
    }
  }

  if (loading) {
    return (
      <PageShell title="Engagements" subtitle="Loading...">
        <div className="text-center py-12">
          <div className="inline-block w-8 h-8 border-4 border-purple-500 border-t-transparent rounded-full animate-spin" />
          <p className="mt-4 text-slate-400">Loading engagements...</p>
        </div>
      </PageShell>
    )
  }

  return (
    <PageShell
      title={`Engagements${client?.name ? ` — ${client.name}` : ''}`}
      subtitle="Formalize Red Team execution windows and ROE per client"
    >
      <div className="max-w-5xl mx-auto space-y-6">
        <div className="flex items-center justify-between">
          <Link to={`/clients/${clientId}`} className="text-sm text-slate-400 hover:text-slate-200">
            ← Back to Client
          </Link>
          <div className="text-xs text-slate-500 font-mono">
            Client ID: {clientId}
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
              <h2 className="text-lg font-semibold text-white">Create Engagement</h2>
              <p className="text-xs text-slate-400 mt-1">Tracks ROE mode and time window for authorized execution.</p>
            </div>
            <button
              type="button"
              onClick={createEngagement}
              disabled={creating}
              className="px-4 py-2 bg-purple-600 text-white rounded-lg hover:bg-purple-700 disabled:opacity-50"
            >
              {creating ? 'Creating…' : 'Create'}
            </button>
          </div>

          <div className="mt-5 grid grid-cols-1 md:grid-cols-2 gap-4">
            <div>
              <label className="block text-xs text-slate-400 mb-1">Name</label>
              <input
                className="w-full px-3 py-2 bg-slate-900/60 border border-slate-700 rounded-lg text-white"
                value={name}
                onChange={(e) => setName(e.target.value)}
                placeholder="Q2 2026 Red Team — External Perimeter"
              />
            </div>

            <div>
              <label className="block text-xs text-slate-400 mb-1">ROE Mode</label>
              <select
                className="w-full px-3 py-2 bg-slate-900/60 border border-slate-700 rounded-lg text-white"
                value={roeMode}
                onChange={(e) => setRoeMode(e.target.value)}
              >
                <option value="safe_proofs">safe_proofs (recommended)</option>
                <option value="weaponized_god_mode">weaponized_god_mode (high risk)</option>
              </select>
            </div>

            <div>
              <label className="block text-xs text-slate-400 mb-1">Start</label>
              <input
                type="datetime-local"
                className="w-full px-3 py-2 bg-slate-900/60 border border-slate-700 rounded-lg text-white"
                value={startAt}
                onChange={(e) => setStartAt(e.target.value)}
              />
            </div>

            <div>
              <label className="block text-xs text-slate-400 mb-1">End (optional)</label>
              <input
                type="datetime-local"
                className="w-full px-3 py-2 bg-slate-900/60 border border-slate-700 rounded-lg text-white"
                value={endAt}
                onChange={(e) => setEndAt(e.target.value)}
              />
            </div>

            <div className="md:col-span-2">
              <label className="block text-xs text-slate-400 mb-1">Notes (optional)</label>
              <textarea
                className="w-full min-h-24 px-3 py-2 bg-slate-900/60 border border-slate-700 rounded-lg text-white"
                value={notes}
                onChange={(e) => setNotes(e.target.value)}
                placeholder="Exclusions, deconfliction contacts, allowed hours, safe mode constraints…"
              />
            </div>
          </div>
        </div>

        <div className="p-6 bg-slate-900/30 border border-slate-800 rounded-xl">
          <div className="flex items-center justify-between">
            <h2 className="text-lg font-semibold text-white">Engagement History</h2>
            <span className="text-xs text-slate-500">{engagements.length} total</span>
          </div>

          {engagements.length === 0 ? (
            <div className="text-center py-10 text-slate-500">
              No engagements yet.
            </div>
          ) : (
            <div className="mt-4 space-y-3">
              {engagements.map((e) => (
                <div key={e.id} className="p-4 border border-slate-800 rounded-lg bg-black/20">
                  <div className="flex items-start justify-between gap-4">
                    <div className="min-w-0">
                      <div className="text-white font-medium truncate">{e.name}</div>
                      <div className="mt-1 text-xs text-slate-400 font-mono">
                        {e.status} · {e.roe_mode} · {e.start_at?.slice(0, 19).replace('T', ' ')}
                        {e.end_at ? ` → ${String(e.end_at).slice(0, 19).replace('T', ' ')}` : ''}
                      </div>
                    </div>
                    <div className="flex items-center gap-2 shrink-0">
                      <Link
                        to={`/api/engagements/${e.id}`}
                        className="px-3 py-1 text-xs border border-slate-700 text-slate-300 rounded hover:bg-slate-800"
                        onClick={(ev) => ev.preventDefault()}
                        title="Engagement details are available via API; UI detail view will be added next."
                      >
                        API
                      </Link>
                      {e.status !== 'closed' && (
                        <button
                          type="button"
                          onClick={() => closeEngagement(e)}
                          className="px-3 py-1 text-xs border border-red-500/40 text-red-300 rounded hover:bg-red-900/20"
                        >
                          Close
                        </button>
                      )}
                    </div>
                  </div>
                </div>
              ))}
            </div>
          )}
        </div>
      </div>
    </PageShell>
  )
}

