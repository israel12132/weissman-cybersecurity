import React, { useEffect, useRef, useState, useCallback } from 'react'
import { apiEventSourceUrl } from '../../lib/apiBase'

function phaseStyle(phase) {
  const p = (phase || '').toLowerCase()
  if (p === 'proposer') {
    return { border: '1px solid rgba(248,113,113,0.45)', color: '#fecaca', bg: 'rgba(127,29,29,0.25)' }
  }
  if (p === 'critic') {
    return { border: '1px solid rgba(96,165,250,0.5)', color: '#bfdbfe', bg: 'rgba(30,58,138,0.35)' }
  }
  if (p === 'bypass') {
    return { border: '1px solid rgba(251,191,36,0.45)', color: '#fde68a', bg: 'rgba(120,53,15,0.3)' }
  }
  if (p === 'vaccine') {
    return { border: '1px solid rgba(52,211,153,0.5)', color: '#a7f3d0', bg: 'rgba(6,78,59,0.35)' }
  }
  return { border: '1px solid rgba(148,163,184,0.35)', color: '#e2e8f0', bg: 'rgba(15,23,42,0.6)' }
}

export default function CeoWarRoomStream({ jobId, onJobIdChange }) {
  const [lines, setLines] = useState([])
  const [status, setStatus] = useState('idle')
  const [since, setSince] = useState(0)
  const esRef = useRef(null)
  const scrollRef = useRef(null)
  const sinceRef = useRef(0)

  const stop = useCallback(() => {
    if (esRef.current) {
      esRef.current.close()
      esRef.current = null
    }
    setStatus('stopped')
  }, [])

  const start = useCallback(() => {
    const jid = (jobId || '').trim()
    if (!jid) {
      setStatus('error: enter async job UUID')
      return
    }
    stop()
    setLines([])
    sinceRef.current = 0
    setSince(0)
    setStatus('connecting')
    const path = '/api/ceo/council/sessions/' + encodeURIComponent(jid) + '/stream?since=0'
    const es = new EventSource(apiEventSourceUrl(path), { withCredentials: true })
    esRef.current = es

    es.addEventListener('war_room', (ev) => {
      try {
        const row = JSON.parse(ev.data)
        const id = typeof row.id === 'number' ? row.id : 0
        sinceRef.current = Math.max(sinceRef.current, id)
        setSince(sinceRef.current)
        setLines((prev) => [...prev, row])
      } catch (_) {
        setLines((prev) => [
          ...prev,
          {
            phase: 'parse_error',
            severity: 'low',
            payload: { raw: ev.data },
            ts: new Date().toISOString(),
          },
        ])
      }
    })

    es.addEventListener('error', (ev) => {
      try {
        const row = JSON.parse(ev.data || '{}')
        setLines((prev) => [
          ...prev,
          { phase: 'stream_error', severity: 'high', payload: row, ts: new Date().toISOString() },
        ])
      } catch (_) {
        setLines((prev) => [
          ...prev,
          {
            phase: 'stream_error',
            severity: 'high',
            payload: { message: 'SSE error' },
            ts: new Date().toISOString(),
          },
        ])
      }
    })

    es.onerror = () => {
      setStatus((s) => (s === 'connecting' ? 'reconnecting' : 'connection error'))
    }

    es.onopen = () => setStatus('live')
  }, [jobId, stop])

  useEffect(() => () => stop(), [stop])

  useEffect(() => {
    const el = scrollRef.current
    if (el) el.scrollTop = el.scrollHeight
  }, [lines])

  return (
    <section className="rounded-lg border border-white/10 bg-black/40 backdrop-blur-sm overflow-hidden">
      <div className="px-4 py-3 border-b border-white/10 flex flex-wrap items-end gap-3">
        <div className="flex-1 min-w-[200px]">
          <label className="block text-[10px] uppercase tracking-widest text-slate-500 mb-1 font-mono">
            Async job UUID (session)
          </label>
          <input
            value={jobId}
            onChange={(e) => onJobIdChange(e.target.value)}
            placeholder="genesis job id"
            className="w-full font-mono text-sm bg-slate-950/80 border border-white/15 rounded px-3 py-2 text-slate-100 placeholder:text-slate-600"
          />
        </div>
        <div className="flex gap-2">
          <button
            type="button"
            onClick={start}
            className="px-4 py-2 rounded bg-red-950/80 border border-red-500/40 text-red-100 text-xs font-mono uppercase tracking-wide hover:bg-red-900/80"
          >
            Subscribe SSE
          </button>
          <button
            type="button"
            onClick={stop}
            className="px-4 py-2 rounded bg-slate-900 border border-white/15 text-slate-300 text-xs font-mono uppercase tracking-wide hover:bg-slate-800"
          >
            Stop
          </button>
        </div>
        <div className="text-[10px] font-mono text-slate-500">
          cursor: <span className="text-cyan-400/90">{since}</span> · {status}
        </div>
      </div>
      <div
        ref={scrollRef}
        className="h-[min(420px,50vh)] overflow-y-auto p-3 font-mono text-[11px] leading-relaxed space-y-2 bg-[#050508]"
      >
        {lines.length === 0 && (
          <div className="text-slate-600 italic">No events yet. Subscribe with a council job session id.</div>
        )}
        {lines.map((row, i) => {
          const phase = row.phase || 'event'
          const sev = row.severity || 'info'
          const st = phaseStyle(phase)
          return (
            <div key={(row.id != null ? row.id : i) + '-' + (row.ts || i)} className="rounded-md p-2" style={st}>
              <div className="flex flex-wrap gap-2 items-baseline mb-1 opacity-90">
                <span className="font-bold uppercase tracking-tight">{phase}</span>
                <span className="text-[10px] px-1.5 py-0.5 rounded bg-black/30 border border-white/10">{sev}</span>
                <span className="text-[10px] text-slate-400">{row.ts || '—'}</span>
              </div>
              <pre className="whitespace-pre-wrap break-words text-[10px] opacity-95">
                {JSON.stringify(row.payload != null ? row.payload : row, null, 2)}
              </pre>
            </div>
          )
        })}
      </div>
    </section>
  )
}
