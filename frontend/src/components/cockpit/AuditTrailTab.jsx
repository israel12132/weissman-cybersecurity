import React, { useEffect, useState } from 'react'
import { formatApiErrorResponse } from '../../lib/apiError.js'
import { sanitizeFindingPlainText } from '../../lib/sanitizeFinding.js'
import { apiFetch } from '../../lib/apiBase'

export default function AuditTrailTab() {
  const [rows, setRows] = useState([])
  const [err, setErr] = useState(null)
  const [loading, setLoading] = useState(true)

  useEffect(() => {
    let cancelled = false
    ;(async () => {
      setLoading(true)
      setErr(null)
      try {
        const r = await apiFetch('/api/audit-logs')
        if (cancelled) return
        if (!r.ok) {
          setRows([])
          setErr(await formatApiErrorResponse(r))
          return
        }
        const data = await r.json()
        if (!Array.isArray(data)) {
          setRows([])
          setErr('Unexpected response from audit API (expected a list).')
          return
        }
        setRows(data)
      } catch (e) {
        if (!cancelled) {
          setRows([])
          setErr(e?.message || 'Failed to load audit trail')
        }
      } finally {
        if (!cancelled) setLoading(false)
      }
    })()
    return () => {
      cancelled = true
    }
  }, [])

  return (
    <div className="p-6 text-white/90 max-w-6xl mx-auto">
      <h2 className="text-lg font-semibold mb-1 tracking-tight text-white">Audit trail</h2>
      <p className="text-xs text-white/50 mb-6 uppercase tracking-widest">
        Immutable log — login, scans, safe mode, auto-heal, RoE changes
      </p>
      {loading && <p className="text-sm text-white/40">Loading…</p>}
      {err && (
        <div className="text-sm text-red-300 mb-4 rounded-lg border border-red-500/40 bg-red-950/30 px-4 py-3" role="alert">
          {err}
        </div>
      )}
      {!loading && !err && (
        <div className="overflow-x-auto rounded-xl border border-white/10 bg-black/30 backdrop-blur-sm">
          <table className="w-full text-left text-xs">
            <thead>
              <tr className="border-b border-white/10 text-white/50 uppercase tracking-wider">
                <th className="p-3 font-medium">Time</th>
                <th className="p-3 font-medium">User</th>
                <th className="p-3 font-medium">User ID</th>
                <th className="p-3 font-medium">Action</th>
                <th className="p-3 font-medium">IP</th>
                <th className="p-3 font-medium">Details</th>
              </tr>
            </thead>
            <tbody>
              {rows.length === 0 && (
                <tr>
                  <td colSpan={6} className="p-6 text-center text-white/40">
                    No audit entries yet
                  </td>
                </tr>
              )}
              {rows.map((r) => (
                <tr key={r.id} className="border-b border-white/5 hover:bg-white/[0.03] font-mono">
                  <td className="p-3 text-white/70 whitespace-nowrap">{r.timestamp || '—'}</td>
                  <td className="p-3 text-[#22d3ee]/90 max-w-[140px] truncate" title={sanitizeFindingPlainText(r.user, 500)}>
                    {sanitizeFindingPlainText(r.user, 500) || '—'}
                  </td>
                  <td className="p-3 text-white/50 whitespace-nowrap tabular-nums">
                    {r.user_id != null ? String(r.user_id) : '—'}
                  </td>
                  <td className="p-3 text-amber-200/90 whitespace-nowrap">{sanitizeFindingPlainText(r.action_type, 200) || '—'}</td>
                  <td className="p-3 text-white/50">{sanitizeFindingPlainText(r.ip_address, 80) || '—'}</td>
                  <td className="p-3 text-white/60 max-w-md break-words">{sanitizeFindingPlainText(r.details, 8000) || '—'}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  )
}
