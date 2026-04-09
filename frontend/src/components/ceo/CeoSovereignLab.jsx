import React, { useCallback, useEffect, useState } from 'react'
import { apiFetch } from '../../lib/apiBase'

export default function CeoSovereignLab() {
  const [rows, setRows] = useState([])
  const [loading, setLoading] = useState(true)
  const [err, setErr] = useState('')
  const [busyId, setBusyId] = useState(null)
  const [toast, setToast] = useState('')

  const load = useCallback(async () => {
    setLoading(true)
    setErr('')
    try {
      const r = await apiFetch('/api/ceo/sovereign/buffer?limit=200')
      const d = await r.json().catch(() => ({}))
      if (!r.ok) throw new Error(d.detail || r.statusText)
      setRows(Array.isArray(d) ? d : [])
    } catch (e) {
      setErr(e.message || 'load failed')
      setRows([])
    } finally {
      setLoading(false)
    }
  }, [])

  useEffect(() => {
    load()
  }, [load])

  const trigger = async (bufferId) => {
    setBusyId(bufferId)
    setToast('')
    try {
      const r = await apiFetch('/api/ceo/sovereign/trigger', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          buffer_id: bufferId,
          trace: 'ceo-sovereign-shadow-preflight',
        }),
      })
      const d = await r.json().catch(() => ({}))
      if (!r.ok) throw new Error(d.detail || r.statusText)
      setToast('Enqueued job ' + (d.job_id || ''))
      await load()
    } catch (e) {
      setToast(e.message || 'enqueue failed')
    } finally {
      setBusyId(null)
    }
  }

  return (
    <div className="rounded-lg border border-violet-500/25 bg-violet-950/10 overflow-hidden">
      <div className="px-4 py-3 border-b border-white/10 flex justify-between items-center flex-wrap gap-2">
        <div>
          <h2 className="text-sm font-semibold text-violet-100 uppercase tracking-widest">Sovereign lab</h2>
          <p className="text-[10px] font-mono text-slate-500 mt-1">
            Learning buffer: WAF failures queued for critic and polymorphic bypass synthesis.
          </p>
        </div>
        <button
          type="button"
          onClick={load}
          className="text-xs font-mono px-3 py-1.5 rounded border border-violet-400/30 text-violet-200 hover:bg-violet-950/50"
        >
          Refresh
        </button>
      </div>
      {toast && (
        <div className="px-4 py-2 text-[11px] font-mono text-slate-300 border-b border-white/10 bg-black/30">
          {toast}
        </div>
      )}
      {loading && <p className="p-4 text-xs text-slate-500 font-mono">Loading buffer…</p>}
      {err && <p className="p-4 text-xs text-red-400 font-mono">{err}</p>}
      <div className="overflow-x-auto max-h-[min(480px,55vh)] overflow-y-auto">
        <table className="w-full text-left text-xs font-mono text-slate-300">
          <thead className="sticky top-0 bg-slate-950/95 border-b border-white/10 text-[10px] uppercase text-slate-500">
            <tr>
              <th className="p-2 pl-4">ID</th>
              <th className="p-2">Target FP</th>
              <th className="p-2">Status</th>
              <th className="p-2">Updated</th>
              <th className="p-2 pr-4">Action</th>
            </tr>
          </thead>
          <tbody>
            {rows.map((row) => (
              <tr key={row.id} className="border-b border-white/5">
                <td className="p-2 pl-4 text-violet-300">{row.id}</td>
                <td className="p-2 max-w-[200px] truncate" title={row.target_fingerprint}>
                  {row.target_fingerprint}
                </td>
                <td className="p-2">{row.status}</td>
                <td className="p-2 text-slate-500">{row.updated_at}</td>
                <td className="p-2 pr-4">
                  <button
                    type="button"
                    disabled={busyId === row.id}
                    onClick={() => trigger(row.id)}
                    className="text-[10px] font-mono uppercase px-2 py-1 rounded bg-violet-900/60 border border-violet-400/35 text-violet-100 disabled:opacity-40"
                  >
                    {busyId === row.id ? '…' : 'Trigger shadow preflight'}
                  </button>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  )
}
