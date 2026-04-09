/**
 * Phase 5: Swarm Mind — live multi-agent graph (Recon → Exploitation ← Stealth) via WebSocket.
 */
import React, { useCallback, useEffect, useRef, useState } from 'react'
import { useClient } from '../../context/ClientContext'
import { Network, Play, Radio, Bot } from 'lucide-react'
import { apiFetch } from '../../lib/apiBase'

const WS_BASE = () => {
  if (typeof window === 'undefined') return ''
  const proto = window.location.protocol === 'https:' ? 'wss:' : 'ws:'
  return `${proto}//${window.location.host}`
}

const AGENT_COLORS = {
  ReconAgent: '#22d3ee',
  ExploitationAgent: '#f472b6',
  StealthAgent: '#a78bfa',
  SwarmCoordinator: '#34d399',
}

export default function SwarmMindTab() {
  const { selectedClientId } = useClient()
  const [events, setEvents] = useState([])
  const [wsConnected, setWsConnected] = useState(false)
  const [running, setRunning] = useState(false)
  const wsRef = useRef(null)
  const listEnd = useRef(null)

  useEffect(() => {
    const wsUrl = `${WS_BASE()}/ws/swarm`
    const ws = new WebSocket(wsUrl)
    wsRef.current = ws
    ws.onopen = () => setWsConnected(true)
    ws.onclose = () => setWsConnected(false)
    ws.onmessage = (ev) => {
      try {
        const msg = JSON.parse(ev.data)
        if (msg.type === 'swarm') {
          setEvents((prev) => [...prev.slice(-200), msg])
        }
      } catch (_) {}
    }
    return () => {
      ws.close()
    }
  }, [])

  useEffect(() => {
    listEnd.current?.scrollIntoView({ behavior: 'smooth' })
  }, [events])

  const runSwarm = useCallback(async () => {
    if (!selectedClientId) return
    setRunning(true)
    try {
      await apiFetch(`/api/clients/${selectedClientId}/swarm/run`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
      })
    } catch (_) {}
    setTimeout(() => setRunning(false), 500)
  }, [selectedClientId])

  if (!selectedClientId) {
    return (
      <div className="p-8 rounded-2xl bg-black/40 backdrop-blur-md border border-white/10 text-center text-white/70">
        Select a client to run the multi-agent swarm.
      </div>
    )
  }

  const byAgent = events.reduce((acc, e) => {
    const a = e.agent || 'unknown'
    acc[a] = (acc[a] || 0) + 1
    return acc
  }, {})

  return (
    <div className="space-y-6">
      <div className="flex items-center gap-2">
        <Network className="w-5 h-5 text-violet-400" />
        <h2 className="text-lg font-semibold text-white">Swarm Mind</h2>
        <span
          className={`ml-2 text-xs px-2 py-0.5 rounded-full ${wsConnected ? 'bg-emerald-500/20 text-emerald-400' : 'bg-white/10 text-white/50'}`}
        >
          <Radio className="w-3 h-3 inline mr-1" />
          {wsConnected ? 'stream' : 'offline'}
        </span>
      </div>

      <div className="rounded-2xl bg-black/40 border border-violet-500/20 p-4">
        <p className="text-xs text-white/60 mb-4">
          <strong className="text-violet-300">Architecture:</strong> ReconAgent discovers ASM HTTP(S) targets and delegates over{' '}
          <code className="text-cyan-400">mpsc</code> to ExploitationAgent. Each payload is reviewed by StealthAgent (Shannon entropy → WAF
          risk) before AI red-team execution. Events broadcast on this channel.
        </p>
        <div className="flex flex-wrap gap-4 items-center justify-between">
          <div className="flex gap-6 text-[11px]">
            {Object.entries(byAgent).map(([agent, n]) => (
              <div key={agent} className="flex items-center gap-2">
                <Bot className="w-4 h-4" style={{ color: AGENT_COLORS[agent] || '#94a3b8' }} />
                <span className="text-white/80">{agent}</span>
                <span className="text-white/40">{n}</span>
              </div>
            ))}
          </div>
          <button
            type="button"
            onClick={runSwarm}
            disabled={running}
            className="flex items-center gap-2 px-4 py-2 rounded-xl border border-violet-500/50 bg-violet-500/10 text-violet-300 hover:bg-violet-500/20 disabled:opacity-50"
          >
            <Play className="w-4 h-4" />
            {running ? 'Queued…' : 'Run swarm on client'}
          </button>
        </div>
        <div className="mt-4 grid grid-cols-1 md:grid-cols-3 gap-2 text-[10px] text-white/45 font-mono">
          <div className="rounded-lg border border-cyan-500/20 bg-cyan-500/5 p-2 text-center">Recon → targets</div>
          <div className="rounded-lg border border-fuchsia-500/20 bg-fuchsia-500/5 p-2 text-center">Exploit ← Stealth verdict</div>
          <div className="rounded-lg border border-violet-500/20 bg-violet-500/5 p-2 text-center">Broadcast → UI</div>
        </div>
        <p className="mt-3 text-[10px] text-white/40">
          Global ingest: set <code className="text-cyan-500/80">WEISSMAN_THREAT_INGEST_CRON=1</code> on the engine, or call{' '}
          <code className="text-cyan-500/80">POST /api/threat-ingest/run</code>. Register SBOM rows via{' '}
          <code className="text-cyan-500/80">POST /api/clients/:id/sbom/components</code> for package correlation.
        </p>
      </div>

      <div className="rounded-2xl bg-black/50 border border-white/10 overflow-hidden">
        <div className="px-4 py-2 border-b border-white/10 text-sm text-white/80">Inter-agent traffic (live)</div>
        <ul className="max-h-[420px] overflow-y-auto p-3 space-y-2 font-mono text-[11px]">
          {events.length === 0 && <li className="text-white/40">No events yet. Press Run swarm.</li>}
          {events.map((e, i) => (
            <li
              key={`${e.ts}-${i}`}
              className="rounded-lg border border-white/5 bg-black/40 px-3 py-2"
              style={{ borderLeftWidth: 3, borderLeftColor: AGENT_COLORS[e.agent] || '#64748b' }}
            >
              <div className="flex flex-wrap gap-2 text-white/90">
                <span style={{ color: AGENT_COLORS[e.agent] || '#94a3b8' }}>{e.agent}</span>
                <span className="text-white/50">·</span>
                <span>{e.event}</span>
              </div>
              {e.detail && (
                <pre className="mt-1 text-white/55 whitespace-pre-wrap break-all max-h-24 overflow-y-auto">
                  {typeof e.detail === 'string' ? e.detail : JSON.stringify(e.detail, null, 0)}
                </pre>
              )}
            </li>
          ))}
          <div ref={listEnd} />
        </ul>
      </div>
    </div>
  )
}
