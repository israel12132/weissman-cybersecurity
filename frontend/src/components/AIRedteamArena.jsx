/**
 * Module 6: AI Red Teaming Arena — split-screen attacker vs defender, live judge status.
 * Left: Our LLM (Attacker) payloads. Right: Target LLM (Defender) responses. Center: JAILBREAK SUCCESS / SECURE.
 */
import { useCallback, useEffect, useRef, useState } from 'react'
import { useParams, Link } from 'react-router-dom'
import { apiFetch } from '../lib/apiBase'

const WS_BASE = () => {
  if (typeof window === 'undefined') return ''
  const proto = window.location.protocol === 'https:' ? 'wss:' : 'ws:'
  return `${proto}//${window.location.host}`
}

export default function AIRedteamArena() {
  const { clientId } = useParams()
  const [target, setTarget] = useState('')
  const [aiEndpoint, setAiEndpoint] = useState('')
  const [client, setClient] = useState(null)
  const [running, setRunning] = useState(false)
  const [error, setError] = useState('')
  const [attackerLog, setAttackerLog] = useState([])
  const [defenderLog, setDefenderLog] = useState([])
  const [centerStatus, setCenterStatus] = useState(null) // { status: 'ANALYZING_RESPONSE' | 'JAILBREAK_SUCCESS' | 'SECURE', verdict?, explanation? }
  const wsRef = useRef(null)

  const fetchClient = useCallback(() => {
    if (!clientId) return
    apiFetch('/api/clients')
      .then((r) => (r.ok ? r.json() : Promise.reject()))
      .then((list) => {
        const c = Array.isArray(list) ? list.find((x) => String(x.id) === String(clientId)) : null
        setClient(c || null)
        if (c?.domains_json) {
          try {
            const domains = JSON.parse(c.domains_json)
            if (domains?.[0]) setTarget(domains[0])
          } catch (_) {}
        }
      })
      .catch(() => setClient(null))
  }, [clientId])

  useEffect(() => {
    fetchClient()
  }, [fetchClient])

  const startScan = useCallback(() => {
    const body = {}
    if (target.trim()) body.target = target.trim()
    if (clientId) body.client_id = String(clientId)
    if (aiEndpoint.trim()) body.ai_endpoint = aiEndpoint.trim()
    if (!body.target && !body.client_id) {
      setError('Enter target URL or open from a client.')
      return
    }
    setError('')
    setRunning(true)
    setAttackerLog([])
    setDefenderLog([])
    setCenterStatus(null)

    apiFetch('/api/ai-redteam/run', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(body),
    })
      .then((r) => (r.ok ? r.json() : Promise.reject(new Error('Start failed'))))
      .then(() => {
        const wsUrl = `${WS_BASE()}/ws/ai-redteam`
        const ws = new WebSocket(wsUrl)
        wsRef.current = ws
        ws.onmessage = (ev) => {
          try {
            const e = JSON.parse(ev.data)
            if (e.phase === 'payload' && e.payload != null) {
              setAttackerLog((prev) => [...prev, { type: 'payload', text: e.payload, index: e.index }])
            }
            if (e.phase === 'response' && e.response != null) {
              setDefenderLog((prev) => [...prev, { type: 'response', text: e.response, index: e.index }])
            }
            if (e.phase === 'judge') {
              setCenterStatus({
                status: e.status || (e.verdict === 'YES' ? 'JAILBREAK_SUCCESS' : 'SECURE'),
                verdict: e.verdict,
                explanation: e.explanation,
              })
              if (e.verdict === 'YES') {
                setAttackerLog((prev) => [...prev, { type: 'judge', text: `✓ JAILBREAK: ${e.explanation || ''}`, index: e.index }])
              } else {
                setAttackerLog((prev) => [...prev, { type: 'judge', text: `✗ SECURE: ${e.explanation || ''}`, index: e.index }])
              }
            }
            if (e.status === 'ANALYZING_RESPONSE') {
              setCenterStatus((prev) => ({ ...prev, status: 'ANALYZING_RESPONSE' }))
            }
          } catch (_) {}
        }
        ws.onclose = () => setRunning(false)
        ws.onerror = () => setRunning(false)
      })
      .catch((e) => {
        setError(e?.message || 'Failed to start')
        setRunning(false)
      })
  }, [target, clientId, aiEndpoint])

  useEffect(() => {
    return () => {
      if (wsRef.current) wsRef.current.close()
    }
  }, [])

  return (
    <div className="min-h-screen bg-slate-950 text-slate-200 p-6">
      <div className="max-w-7xl mx-auto">
        <div className="flex items-center justify-between mb-6">
          <div className="flex items-center gap-4">
            <Link to="/" className="text-cyan-400 hover:text-cyan-300 text-sm font-medium">
              ← War Room
            </Link>
            <h1 className="text-2xl font-bold text-white tracking-tight">
              AI Red Teaming Arena
            </h1>
          </div>
          <span className="text-slate-500 text-sm">AI vs AI • OWASP LLM01</span>
        </div>

        <div className="grid grid-cols-1 lg:grid-cols-4 gap-4 mb-6">
          <div className="lg:col-span-2">
            <label className="block text-slate-400 text-xs uppercase tracking-wider mb-2">Target URL (or use client)</label>
            <input
              type="text"
              value={target}
              onChange={(e) => setTarget(e.target.value)}
              placeholder="https://target.com"
              className="w-full rounded-lg bg-slate-800 border border-slate-600 px-3 py-2 text-sm text-white placeholder-slate-500"
              disabled={running}
            />
          </div>
          <div className="lg:col-span-2">
            <label className="block text-slate-400 text-xs uppercase tracking-wider mb-2">Target AI Endpoint URL (optional override)</label>
            <input
              type="text"
              value={aiEndpoint}
              onChange={(e) => setAiEndpoint(e.target.value)}
              placeholder="https://target.com/chat or leave empty"
              className="w-full rounded-lg bg-slate-800 border border-slate-600 px-3 py-2 text-sm text-white placeholder-slate-500"
              disabled={running}
            />
          </div>
        </div>
        <div className="flex gap-2 mb-6">
          <button
            onClick={startScan}
            disabled={running}
            className="px-4 py-2 rounded-lg bg-rose-600 hover:bg-rose-500 disabled:bg-slate-600 text-white font-medium text-sm"
          >
            {running ? 'Running…' : 'Launch AI vs AI'}
          </button>
          {clientId && (
            <span className="text-slate-500 text-sm self-center">Client ID: {clientId} {client?.name && `(${client.name})`}</span>
          )}
        </div>
        {error && <p className="text-red-400 text-sm mb-4">{error}</p>}

        {/* Center: Live status */}
        <div className="mb-6 flex justify-center">
          <div
            className={`rounded-xl border-2 px-6 py-4 min-w-[280px] text-center font-bold text-lg ${
              centerStatus?.status === 'JAILBREAK_SUCCESS'
                ? 'border-red-500 bg-red-500/10 text-red-400'
                : centerStatus?.status === 'SECURE'
                  ? 'border-emerald-500 bg-emerald-500/10 text-emerald-400'
                  : 'border-slate-600 bg-slate-800/80 text-slate-300'
            }`}
          >
            {centerStatus?.status === 'JAILBREAK_SUCCESS' && <>JAILBREAK SUCCESS</>}
            {centerStatus?.status === 'SECURE' && <>SECURE</>}
            {(centerStatus?.status === 'ANALYZING_RESPONSE' || !centerStatus) && (running ? 'ANALYZING RESPONSE…' : '—')}
            {centerStatus?.explanation && (
              <p className="text-sm font-normal mt-2 opacity-90">{centerStatus.explanation}</p>
            )}
          </div>
        </div>

        {/* Split-screen terminals */}
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
          <div className="rounded-xl bg-slate-900/80 border border-slate-700/60 overflow-hidden">
            <div className="bg-rose-900/40 border-b border-slate-700 px-4 py-2 font-semibold text-rose-300">
              Our LLM (Attacker)
            </div>
            <div className="h-80 overflow-y-auto p-4 font-mono text-sm bg-slate-950/80">
              {attackerLog.length === 0 && (
                <span className="text-slate-500">Generated adversarial payloads will stream here…</span>
              )}
              {attackerLog.map((entry, i) => (
                <div key={i} className="mb-2">
                  {entry.type === 'payload' && (
                    <div className="text-amber-200 break-words">&gt; {entry.text}</div>
                  )}
                  {entry.type === 'judge' && (
                    <div className="text-slate-400 text-xs mt-1">{entry.text}</div>
                  )}
                </div>
              ))}
            </div>
          </div>
          <div className="rounded-xl bg-slate-900/80 border border-slate-700/60 overflow-hidden">
            <div className="bg-slate-700/40 border-b border-slate-700 px-4 py-2 font-semibold text-slate-300">
              Target LLM (Defender)
            </div>
            <div className="h-80 overflow-y-auto p-4 font-mono text-sm bg-slate-950/80">
              {defenderLog.length === 0 && (
                <span className="text-slate-500">Target responses will stream here…</span>
              )}
              {defenderLog.map((entry, i) => (
                <div key={i} className="mb-2 text-slate-300 break-words">
                  {entry.text}
                </div>
              ))}
            </div>
          </div>
        </div>
        <p className="text-slate-500 text-xs mt-4">
          Findings are saved with source <code className="bg-slate-800 px-1 rounded">ai_adversarial_redteam</code> and appear in the Executive PDF Report.
        </p>
      </div>
    </div>
  )
}
