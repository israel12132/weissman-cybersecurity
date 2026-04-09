import React, { useCallback, useEffect, useState } from 'react'
import { apiUrl, apiFetch } from '../../lib/apiBase'

const TABS = [
  { id: 'chain', label: 'Attack chain' },
  { id: 'transcript', label: 'Council transcript' },
  { id: 'patch', label: 'Patch' },
  { id: 'sig', label: 'Detection signature' },
]

export default function CeoVaccineVault() {
  const [rows, setRows] = useState([])
  const [loading, setLoading] = useState(true)
  const [err, setErr] = useState('')
  const [selected, setSelected] = useState(null)
  const [tab, setTab] = useState('chain')
  const [matchBusy, setMatchBusy] = useState(false)
  const [matchMsg, setMatchMsg] = useState('')

  const load = useCallback(async () => {
    setLoading(true)
    setErr('')
    try {
      const r = await apiFetch('/api/ceo/vault?limit=100&offset=0')
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

  const runMatch = async () => {
    if (!selected) return
    setMatchBusy(true)
    setMatchMsg('')
    try {
      const path = '/api/ceo/genesis/vault/' + encodeURIComponent(selected.id) + '/match'
      const r = await apiFetch(path, { method: 'POST' })
      const d = await r.json().catch(() => ({}))
      if (!r.ok) throw new Error(d.detail || r.statusText)
      setMatchMsg(JSON.stringify(d, null, 2))
    } catch (e) {
      setMatchMsg(e.message || 'match failed')
    } finally {
      setMatchBusy(false)
    }
  }

  return (
    <div className="rounded-lg border border-white/10 bg-black/35 overflow-hidden">
      <div className="px-4 py-3 border-b border-white/10 flex flex-wrap justify-between gap-2 items-center">
        <h2 className="text-sm font-semibold text-slate-200 uppercase tracking-widest">Vaccine vault</h2>
        <div className="flex gap-2">
          <a
            href={apiUrl('/api/ceo/vault/export/criticals')}
            className="text-xs font-mono px-3 py-1.5 rounded border border-white/20 text-slate-300 hover:bg-white/5"
            download
          >
            Export criticals CSV
          </a>
          <button
            type="button"
            onClick={load}
            className="text-xs font-mono px-3 py-1.5 rounded border border-cyan-500/30 text-cyan-200 hover:bg-cyan-950/40"
          >
            Refresh
          </button>
        </div>
      </div>
      {loading && <p className="p-4 text-xs text-slate-500 font-mono">Loading…</p>}
      {err && <p className="p-4 text-xs text-red-400 font-mono">{err}</p>}
      <div className="overflow-x-auto max-h-[320px] overflow-y-auto">
        <table className="w-full text-left text-xs font-mono text-slate-300">
          <thead className="sticky top-0 bg-slate-950/95 border-b border-white/10 text-[10px] uppercase text-slate-500">
            <tr>
              <th className="p-2 pl-4">ID</th>
              <th className="p-2">Fingerprint</th>
              <th className="p-2">Severity</th>
              <th className="p-2">Validated</th>
              <th className="p-2 pr-4">Component</th>
            </tr>
          </thead>
          <tbody>
            {rows.map((row) => (
              <tr
                key={row.id}
                onClick={() => {
                  setSelected(row)
                  setTab('chain')
                  setMatchMsg('')
                }}
                className={
                  'border-b border-white/5 cursor-pointer hover:bg-white/5 ' +
                  (selected && selected.id === row.id ? 'bg-cyan-950/30' : '')
                }
              >
                <td className="p-2 pl-4 text-cyan-300/90">{row.id}</td>
                <td className="p-2 max-w-[180px] truncate" title={row.tech_fingerprint}>
                  {row.tech_fingerprint}
                </td>
                <td className="p-2">{row.severity}</td>
                <td className="p-2">{row.preemptive_validated ? 'yes' : 'no'}</td>
                <td className="p-2 pr-4 max-w-[200px] truncate" title={row.component_ref}>
                  {row.component_ref}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>

      {selected && (
        <div className="border-t border-white/10 bg-slate-950/80 p-4 space-y-3">
          <div className="flex flex-wrap gap-2 items-center justify-between">
            <span className="text-xs font-mono text-slate-400">Row #{selected.id}</span>
            <button
              type="button"
              disabled={matchBusy}
              onClick={runMatch}
              className="text-xs font-mono px-3 py-2 rounded bg-violet-950/80 border border-violet-400/40 text-violet-100 disabled:opacity-50"
            >
              {matchBusy ? 'Running…' : 'Run knowledge match'}
            </button>
          </div>
          {matchMsg && (
            <pre className="text-[10px] font-mono text-slate-400 whitespace-pre-wrap break-words max-h-40 overflow-y-auto border border-white/10 rounded p-2">
              {matchMsg}
            </pre>
          )}
          <div className="flex gap-1 border-b border-white/10 pb-2">
            {TABS.map((t) => (
              <button
                key={t.id}
                type="button"
                onClick={() => setTab(t.id)}
                className={
                  'text-[10px] font-mono uppercase px-3 py-1 rounded-t ' +
                  (tab === t.id ? 'bg-white/10 text-cyan-200' : 'text-slate-500 hover:text-slate-300')
                }
              >
                {t.label}
              </button>
            ))}
          </div>
          <div className="min-h-[200px] max-h-[360px] overflow-y-auto text-[11px] font-mono">
            {tab === 'chain' && (
              <pre className="whitespace-pre-wrap break-words text-slate-300">
                {JSON.stringify(selected.attack_chain_json, null, 2)}
              </pre>
            )}
            {tab === 'transcript' && (
              <pre className="whitespace-pre-wrap break-words text-slate-300">
                {JSON.stringify(selected.council_transcript, null, 2)}
              </pre>
            )}
            {tab === 'patch' && (
              <pre className="whitespace-pre-wrap break-words text-emerald-200/90 bg-black/50 p-3 rounded border border-emerald-500/20">
                {selected.remediation_patch || '—'}
              </pre>
            )}
            {tab === 'sig' && (
              <pre className="whitespace-pre-wrap break-words text-amber-200/90 bg-black/50 p-3 rounded border border-amber-500/20">
                {selected.detection_signature || '—'}
              </pre>
            )}
          </div>
        </div>
      )}
    </div>
  )
}
