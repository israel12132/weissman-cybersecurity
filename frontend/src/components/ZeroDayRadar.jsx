/**
 * Module 7: Global Threat Radar — live intel feed, synthesis terminal, zero-day exposure banner.
 */
import { useCallback, useEffect, useRef, useState } from 'react'
import { Link } from 'react-router-dom'
import { apiFetch } from '../lib/apiBase'

const WS_BASE = () => {
  if (typeof window === 'undefined') return ''
  const proto = window.location.protocol === 'https:' ? 'wss:' : 'ws:'
  return `${proto}//${window.location.host}`
}

export default function ZeroDayRadar() {
  const [feedItems, setFeedItems] = useState([])
  const [synthesisLog, setSynthesisLog] = useState([])
  const [scanProgress, setScanProgress] = useState({ current: 0, total: 0 })
  const [exposure, setExposure] = useState(null)
  const [running, setRunning] = useState(false)
  const [loadingFeed, setLoadingFeed] = useState(false)
  const wsRef = useRef(null)
  const feedEndRef = useRef(null)
  const synthEndRef = useRef(null)

  const loadFeed = useCallback(() => {
    setLoadingFeed(true)
    apiFetch('/api/threat-intel/feed')
      .then((r) => (r.ok ? r.json() : Promise.reject()))
      .then((data) => {
        setFeedItems(data?.items ?? [])
      })
      .catch(() => setFeedItems([]))
      .finally(() => setLoadingFeed(false))
  }, [])

  useEffect(() => {
    loadFeed()
    const t = setInterval(loadFeed, 60000)
    return () => clearInterval(t)
  }, [loadFeed])

  useEffect(() => {
    if (feedEndRef.current) feedEndRef.current.scrollIntoView({ behavior: 'smooth' })
  }, [feedItems])

  useEffect(() => {
    if (synthEndRef.current) synthEndRef.current.scrollIntoView({ behavior: 'smooth' })
  }, [synthesisLog])

  const startScan = useCallback(() => {
    setRunning(true)
    setSynthesisLog([])
    setScanProgress({ current: 0, total: 0 })
    setExposure(null)
    apiFetch('/api/threat-intel/run', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({}),
    })
      .then((r) => (r.ok ? r.json() : Promise.reject(new Error('Start failed'))))
      .then(() => {
        const wsUrl = `${WS_BASE()}/ws/threat-intel`
        const ws = new WebSocket(wsUrl)
        wsRef.current = ws
        ws.onmessage = (ev) => {
          try {
            const e = JSON.parse(ev.data)
            if (e.type === 'feed' && e.items) {
              setFeedItems((prev) => [...e.items, ...prev].slice(0, 100))
            }
            if (e.type === 'synthesis') {
              const line = e.probe
                ? `Probe: ${e.item?.external_id ?? e.item?.title} → path=${e.probe?.path ?? '—'}`
                : `Synthesizing AI Probe... (${e.item?.external_id ?? e.item?.title})`
              setSynthesisLog((prev) => [...prev, line])
            }
            if (e.type === 'scan_progress') {
              setScanProgress({ current: e.current ?? 0, total: e.total ?? 0 })
            }
            if (e.type === 'exposure' && e.finding) {
              setExposure(e.finding)
              setSynthesisLog((prev) => [...prev, `ZERO-DAY EXPOSURE: ${e.finding?.title ?? e.finding?.cve_id}`])
            }
          } catch (_) {}
        }
        ws.onclose = () => setRunning(false)
        ws.onerror = () => setRunning(false)
      })
      .catch((err) => {
        setSynthesisLog((prev) => [...prev, `Error: ${err?.message ?? 'Failed to start'}`])
        setRunning(false)
      })
  }, [])

  useEffect(() => {
    return () => { if (wsRef.current) wsRef.current.close() }
  }, [])

  return (
    <div className="min-h-screen bg-slate-950 text-slate-200 p-6">
      <div className="max-w-7xl mx-auto">
        <div className="flex items-center justify-between mb-6">
          <div className="flex items-center gap-4">
            <Link to="/" className="text-cyan-400 hover:text-cyan-300 text-sm font-medium">← War Room</Link>
            <h1 className="text-2xl font-bold text-white tracking-tight">Global Threat Radar</h1>
          </div>
          <span className="text-slate-500 text-sm">NVD + custom feeds • Safe probe synthesis</span>
        </div>

        {exposure && (
          <div className="mb-6 rounded-xl border-2 border-red-500 bg-red-500/20 p-4 animate-pulse">
            <div className="font-bold text-red-400 text-lg">ZERO-DAY EXPOSURE DETECTED</div>
            <div className="text-slate-200 mt-2">{exposure.title}</div>
            <div className="text-sm text-slate-400 mt-1">CVE: {exposure.cve_id} • Target: {exposure.target_url}</div>
            <a
              href={`/command-center/report/${exposure.client_id}`}
              className="inline-block mt-3 text-cyan-400 hover:text-cyan-300 text-sm font-medium"
            >
              View report & remediation →
            </a>
          </div>
        )}

        <div className="flex gap-2 mb-6">
          <button
            onClick={startScan}
            disabled={running}
            className="px-4 py-2 rounded-lg bg-amber-600 hover:bg-amber-500 disabled:bg-slate-600 text-white font-medium text-sm"
          >
            {running ? 'Scanning…' : 'Run Zero-Day Scan'}
          </button>
          <button onClick={loadFeed} disabled={loadingFeed} className="px-4 py-2 rounded-lg bg-slate-700 hover:bg-slate-600 text-sm">
            {loadingFeed ? 'Loading…' : 'Refresh feed'}
          </button>
        </div>

        <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
          <div className="rounded-xl bg-slate-900/80 border border-slate-700/60 overflow-hidden">
            <div className="bg-slate-700/40 border-b border-slate-700 px-4 py-2 font-semibold text-slate-300">
              Live Intelligence Feed
            </div>
            <div className="h-96 overflow-y-auto p-4 space-y-3" id="feed-scroll">
              {feedItems.length === 0 && !loadingFeed && <p className="text-slate-500 text-sm">No feed items. Run refresh or start a scan.</p>}
              {feedItems.map((item, i) => (
                <div key={i} className="rounded-lg bg-slate-800/60 p-3 border border-slate-700/60">
                  <div className="flex items-center gap-2">
                    <span className={`text-xs font-mono px-2 py-0.5 rounded ${item.severity === 'CRITICAL' ? 'bg-red-500/30 text-red-300' : item.severity === 'HIGH' ? 'bg-amber-500/30 text-amber-300' : 'bg-slate-600 text-slate-400'}`}>
                      {item.severity}
                    </span>
                    <span className="text-xs text-slate-500">{item.source}</span>
                  </div>
                  <div className="font-medium text-slate-200 mt-1">{item.external_id || item.title}</div>
                  <div className="text-xs text-slate-400 mt-1 line-clamp-2">{item.description}</div>
                </div>
              ))}
              <div ref={feedEndRef} />
            </div>
          </div>

          <div className="rounded-xl bg-slate-900/80 border border-slate-700/60 overflow-hidden">
            <div className="bg-slate-700/40 border-b border-slate-700 px-4 py-2 font-semibold text-slate-300 flex items-center justify-between">
              Synthesis Terminal
              {scanProgress.total > 0 && (
                <span className="text-xs text-cyan-400">
                  {scanProgress.current}/{scanProgress.total} threats
                </span>
              )}
            </div>
            <div className="h-96 overflow-y-auto p-4 font-mono text-sm bg-slate-950/80">
              {synthesisLog.length === 0 && !running && <p className="text-slate-500">Synthesizing AI Probe... and scan progress will appear here.</p>}
              {synthesisLog.map((line, i) => (
                <div key={i} className={line.startsWith('ZERO-DAY') ? 'text-red-400 font-semibold' : 'text-slate-300'}>
                  &gt; {line}
                </div>
              ))}
              {running && scanProgress.total > 0 && (
                <div className="mt-2">
                  <div className="w-full bg-slate-700 rounded-full h-2">
                    <div
                      className="bg-cyan-500 h-2 rounded-full transition-all duration-300"
                      style={{ width: `${scanProgress.total ? (100 * scanProgress.current) / scanProgress.total : 0}%` }}
                    />
                  </div>
                </div>
              )}
              <div ref={synthEndRef} />
            </div>
          </div>
        </div>
        <p className="text-slate-500 text-xs mt-4">
          Probes are safe detection-only (no destructive exploits). Findings saved with source <code className="bg-slate-800 px-1 rounded">zero_day_radar</code>.
        </p>
      </div>
    </div>
  )
}
