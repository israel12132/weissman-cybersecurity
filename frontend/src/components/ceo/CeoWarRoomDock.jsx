import React, { useCallback, useEffect, useRef, useState } from 'react'
import { useClient } from '../../context/ClientContext'
import { apiUrl, apiFetch, apiEventSourceUrl, formatHttpApiError } from '../../lib/apiBase'

function phaseStyle(phase) {
  const p = (phase || '').toLowerCase()
  if (p === 'connected') {
    return { border: '1px solid rgba(52,211,153,0.45)', color: '#a7f3d0', bg: 'rgba(6,78,59,0.28)' }
  }
  if (p === 'session') {
    return { border: '1px solid rgba(34,211,238,0.4)', color: '#a5f3fc', bg: 'rgba(8,47,73,0.45)' }
  }
  if (p === 'orchestrator' || p === 'pipeline') {
    return { border: '1px solid rgba(56,189,248,0.35)', color: '#e0f2fe', bg: 'rgba(12,74,110,0.35)' }
  }
  if (p === 'finding' || p === 'new_target' || p === 'harvest') {
    return { border: '1px solid rgba(251,191,36,0.4)', color: '#fef3c7', bg: 'rgba(69,26,3,0.35)' }
  }
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
  return { border: '1px solid rgba(34,211,238,0.25)', color: '#e2e8f0', bg: 'rgba(15,23,42,0.65)' }
}

const HEAVY_KINDS = new Set([
  'genesis_eternal_fuzz',
  'council_debate',
  'poe_synthesis_run',
  'deep_fuzz',
  'tenant_full_scan',
  'onboarding_tenant_scan',
  'ascension_wave',
  'general_mission',
])

export default function CeoWarRoomDock() {
  const { selectedClientId } = useClient()
  const [jobs, setJobs] = useState([])
  const [jobsErr, setJobsErr] = useState('')
  const [kindFilter, setKindFilter] = useState('all')
  const [selectedId, setSelectedId] = useState('')
  const [lines, setLines] = useState([])
  const [streamStatus, setStreamStatus] = useState('idle')
  const [since, setSince] = useState(0)
  const esRef = useRef(null)
  const scrollRef = useRef(null)
  const sinceRef = useRef(0)

  const selectedCidRaw = selectedClientId != null ? String(selectedClientId).trim() : ''
  const selectedCidNum = selectedCidRaw ? Number(selectedCidRaw) : NaN
  const jobsScopedToClient = Boolean(selectedCidRaw && Number.isFinite(selectedCidNum))

  const loadJobs = useCallback(async () => {
    setJobsErr('')
    try {
      let path = '/api/ceo/jobs/live'
      const raw = selectedClientId != null ? String(selectedClientId).trim() : ''
      const cid = raw ? Number(raw) : NaN
      if (raw && Number.isFinite(cid))
        path = `/api/ceo/jobs/live?client_id=${encodeURIComponent(String(cid))}`
      const r = await apiFetch(path)
      const d = await r.json().catch(() => ({}))
      if (!r.ok) throw new Error(formatHttpApiError(r, d.detail))
      setJobs(Array.isArray(d.jobs) ? d.jobs : [])
    } catch (e) {
      setJobs([])
      setJobsErr(e.message || 'failed to load jobs')
    }
  }, [selectedClientId])

  useEffect(() => {
    loadJobs()
    const t = setInterval(loadJobs, 5000)
    return () => clearInterval(t)
  }, [loadJobs])

  const stopStream = useCallback(() => {
    if (esRef.current) {
      esRef.current.close()
      esRef.current = null
    }
    setStreamStatus('stopped')
  }, [])

  const startStream = useCallback(
    (jid) => {
      const id = (jid || '').trim()
      if (!id) {
        setStreamStatus('error: no job id')
        return
      }
      stopStream()
      setLines([])
      sinceRef.current = 0
      setSince(0)
      setStreamStatus('connecting')
      const path =
        '/api/ceo/council/sessions/' + encodeURIComponent(id) + '/stream?since=0'
      const es = new EventSource(apiEventSourceUrl(path), { withCredentials: true })
      esRef.current = es

      es.addEventListener('war_room', (ev) => {
        try {
          const row = JSON.parse(ev.data)
          const rowId = typeof row.id === 'number' ? row.id : 0
          sinceRef.current = Math.max(sinceRef.current, rowId)
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

      es.addEventListener('connected', (ev) => {
        try {
          const payload = JSON.parse(ev.data || '{}')
          setStreamStatus('live')
          setLines((prev) => [
            ...prev,
            {
              phase: 'connected',
              severity: 'info',
              payload,
              ts: new Date().toISOString(),
            },
          ])
        } catch (_) {
          setStreamStatus('live')
          setLines((prev) => [
            ...prev,
            {
              phase: 'connected',
              severity: 'info',
              payload: { message: 'SSE stream subscribed', raw: ev.data },
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
        setStreamStatus((s) => (s === 'connecting' ? 'reconnecting' : 'connection error'))
      }

      es.onopen = () => setStreamStatus('live')
    },
    [stopStream],
  )

  useEffect(() => () => stopStream(), [stopStream])

  useEffect(() => {
    const el = scrollRef.current
    if (el) el.scrollTop = el.scrollHeight
  }, [lines])

  const onPickJob = (id) => {
    setSelectedId(id)
    startStream(id)
  }

  const filteredJobs =
    kindFilter === 'heavy'
      ? jobs.filter((j) => HEAVY_KINDS.has((j.kind || '').trim()))
      : jobs

  return (
    <div className="rounded-xl border border-cyan-500/20 bg-gradient-to-b from-slate-950/95 to-black/90 overflow-hidden shadow-[0_0_40px_rgba(34,211,238,0.06)]">
      <div className="px-4 py-3 border-b border-cyan-500/15 flex flex-wrap items-center justify-between gap-2 bg-black/50">
        <div>
          <h3 className="text-[10px] font-mono uppercase tracking-[0.25em] text-cyan-300/90">
            War room · live jobs and event stream
          </h3>
          <p className="text-[10px] text-slate-500 font-mono mt-0.5">
            {jobsScopedToClient
              ? `Showing jobs for the selected client · stream cursor ${since} · ${streamStatus}`
              : `All tenant jobs · stream cursor ${since} · ${streamStatus}`}
            {selectedId ? ` · ${selectedId.slice(0, 8)}…` : ''}
          </p>
          <div className="flex flex-wrap gap-1.5 mt-2">
            {[
              ['all', 'All jobs'],
              ['heavy', 'Heavy ops'],
            ].map(([k, lab]) => (
              <button
                key={k}
                type="button"
                onClick={() => setKindFilter(k)}
                className={`px-2 py-0.5 rounded text-[9px] font-mono uppercase border ${
                  kindFilter === k
                    ? 'border-cyan-400/50 bg-cyan-950/50 text-cyan-200'
                    : 'border-white/10 text-slate-500 hover:text-slate-300'
                }`}
              >
                {lab}
              </button>
            ))}
          </div>
        </div>
        <div className="flex gap-2">
          <button
            type="button"
            onClick={() => loadJobs()}
            className="px-3 py-1.5 rounded-lg border border-white/15 bg-white/5 text-[10px] font-mono uppercase text-slate-300 hover:bg-white/10"
          >
            Refresh jobs
          </button>
          <button
            type="button"
            onClick={stopStream}
            className="px-3 py-1.5 rounded-lg border border-red-500/30 bg-red-950/40 text-[10px] font-mono uppercase text-red-200 hover:bg-red-900/50"
          >
            Stop stream
          </button>
        </div>
      </div>

      <div className="grid lg:grid-cols-5 gap-0 min-h-[320px]">
        <div className="lg:col-span-2 border-b lg:border-b-0 lg:border-r border-cyan-500/10 p-3 max-h-[320px] overflow-y-auto bg-black/30">
          <p className="text-[9px] uppercase tracking-widest text-slate-500 font-mono mb-2">
            {jobsScopedToClient ? 'Live jobs (selected client)' : 'Live jobs (whole tenant)'}
          </p>
          {jobsErr && <p className="text-[10px] text-red-400 font-mono mb-2">{jobsErr}</p>}
          {filteredJobs.length === 0 && !jobsErr && (
            <p className="text-[11px] text-slate-600 font-mono italic">
              {jobs.length === 0 ? 'No pending or running jobs.' : 'No jobs in this filter.'}
            </p>
          )}
          <ul className="space-y-1.5">
            {filteredJobs.map((j) => {
              const id = j.id || ''
              const active = id === selectedId
              return (
                <li key={id}>
                  <button
                    type="button"
                    onClick={() => onPickJob(id)}
                    className={`w-full text-left rounded-lg px-2 py-2 border font-mono text-[10px] transition-all ${
                      active
                        ? 'border-cyan-400/50 bg-cyan-950/50 text-cyan-100'
                        : 'border-white/10 bg-white/[0.03] text-slate-400 hover:border-cyan-500/25 hover:text-slate-200'
                    }`}
                  >
                    <span className="block text-cyan-200/90 truncate" title={id}>
                      {id}
                    </span>
                    <span className="block text-[9px] text-slate-500 mt-0.5">
                      {(j.kind || '—') + ' · ' + (j.status || '—')}
                      {j.worker_id ? ` · ${j.worker_id}` : ''}
                    </span>
                  </button>
                </li>
              )
            })}
          </ul>
        </div>

        <div className="lg:col-span-3 flex flex-col min-h-[280px]">
          <div
            ref={scrollRef}
            className="flex-1 overflow-y-auto p-3 font-mono text-[11px] leading-relaxed space-y-2"
            style={{
              background:
                'linear-gradient(180deg, #020617 0%, #0a0a0f 100%)',
              boxShadow: 'inset 0 0 80px rgba(34,211,238,0.03)',
            }}
          >
            {lines.length === 0 && (
              <div className="text-slate-500 text-[11px] leading-relaxed font-mono space-y-1">
                {!selectedId && (
                  <p className="text-cyan-900/90 italic">Select a job on the left to open its live event stream.</p>
                )}
                {selectedId && streamStatus === 'connecting' && (
                  <p className="flex items-center gap-2 text-cyan-200/70">
                    <span className="inline-block w-3 h-3 border-2 border-cyan-400/30 border-t-cyan-400 rounded-full animate-spin" />
                    Opening SSE to council session stream…
                  </p>
                )}
                {selectedId && streamStatus === 'live' && (
                  <p className="text-slate-500">
                    Connected. Waiting for orchestrator events for this job. Heavy runs (full tenant scan, council,
                    synthesis) stream progress here; short tasks may finish without extra lines.
                  </p>
                )}
                {selectedId &&
                  streamStatus !== 'connecting' &&
                  streamStatus !== 'live' &&
                  !streamStatus.startsWith('error') && (
                    <p className="text-amber-200/70">{streamStatus}</p>
                  )}
                {selectedId && streamStatus.startsWith('error') && (
                  <p className="text-rose-300/90">{streamStatus}</p>
                )}
              </div>
            )}
            {lines.map((row, i) => {
              const phase = row.phase || 'event'
              const sev = row.severity || 'info'
              const st = phaseStyle(phase)
              return (
                <div
                  key={(row.id != null ? row.id : i) + '-' + (row.ts || i)}
                  className="rounded-md p-2"
                  style={st}
                >
                  <div className="flex flex-wrap gap-2 items-baseline mb-1 opacity-90">
                    <span className="font-bold uppercase tracking-tight">{phase}</span>
                    <span className="text-[9px] px-1.5 py-0.5 rounded bg-black/40 border border-white/10">
                      {sev}
                    </span>
                    <span className="text-[9px] text-slate-400">{row.ts || '—'}</span>
                  </div>
                  <pre className="whitespace-pre-wrap break-words text-[10px] opacity-95 text-cyan-50/90">
                    {JSON.stringify(row.payload != null ? row.payload : row, null, 2)}
                  </pre>
                </div>
              )
            })}
          </div>
        </div>
      </div>
    </div>
  )
}
