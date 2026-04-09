import React, { useState, useEffect, useRef, useCallback } from 'react'
import { useParams, Link, useNavigate } from 'react-router-dom'
import { motion } from 'framer-motion'
import { ENGINES_BY_ID, ENGINE_GROUPS } from '../lib/enginesRegistry'
import { apiFetch, apiEventSourceUrl } from '../lib/apiBase'

const MAX_LINES = 500

// ─── Mini terminal ────────────────────────────────────────────────────────────

function Terminal({ lines, engineId }) {
  const termRef = useRef(null)
  useEffect(() => {
    if (termRef.current) {
      termRef.current.scrollTop = termRef.current.scrollHeight
    }
  }, [lines])

  return (
    <div
      ref={termRef}
      className="h-80 overflow-auto rounded-xl bg-black/80 border border-white/5 p-3 font-mono text-[11px] leading-relaxed"
    >
      {lines.length === 0 ? (
        <span className="text-white/20">{`> Engine idle. Run to start streaming output.`}</span>
      ) : (
        lines.map((line, i) => (
          <div
            key={i}
            className={
              line.includes('[ERROR]')
                ? 'text-red-400'
                : line.includes('Completed') || line.includes('completed')
                  ? 'text-[#4ade80]'
                  : 'text-[#4ade80]/80'
            }
          >
            {line}
          </div>
        ))
      )}
    </div>
  )
}

// ─── Config form ──────────────────────────────────────────────────────────────

function ConfigForm({ engine, target, setTarget, timeout, setTimeout, disabled }) {
  return (
    <div className="space-y-4">
      <div>
        <label className="block text-[11px] font-mono text-white/50 uppercase tracking-wider mb-1">
          Target URL / Host
        </label>
        <input
          type="text"
          value={target}
          onChange={(e) => setTarget(e.target.value)}
          placeholder={engine?.requiresTarget ? 'https://target.com' : 'Optional — uses client scope'}
          disabled={disabled}
          className="w-full bg-black/60 border border-white/10 rounded-lg px-3 py-2 text-sm text-white/90 font-mono placeholder-white/25 focus:outline-none focus:border-cyan-500/40 disabled:opacity-50"
        />
      </div>
      <div>
        <label className="block text-[11px] font-mono text-white/50 uppercase tracking-wider mb-1">
          Timeout (seconds)
        </label>
        <input
          type="number"
          value={timeout}
          onChange={(e) => setTimeout(Number(e.target.value))}
          min={10}
          max={3600}
          disabled={disabled}
          className="w-32 bg-black/60 border border-white/10 rounded-lg px-3 py-2 text-sm text-white/90 font-mono focus:outline-none focus:border-cyan-500/40 disabled:opacity-50"
        />
      </div>
    </div>
  )
}

// ─── MITRE card ───────────────────────────────────────────────────────────────

function MitreCard({ technique }) {
  if (!technique) return null
  return (
    <div className="rounded-xl bg-black/40 border border-white/10 p-4">
      <div className="text-[10px] font-mono text-white/40 uppercase tracking-widest mb-2">
        MITRE ATT&amp;CK Mapping
      </div>
      <div className="flex items-center gap-3">
        <span className="text-2xl font-bold font-mono text-[#22d3ee]">{technique}</span>
        <a
          href={`https://attack.mitre.org/techniques/${technique.replace('.', '/')}`}
          target="_blank"
          rel="noopener noreferrer"
          className="text-[11px] text-white/40 hover:text-cyan-400 transition-colors"
        >
          View on MITRE →
        </a>
      </div>
    </div>
  )
}

// ─── Main ─────────────────────────────────────────────────────────────────────

export default function EngineDetail() {
  const { engineId } = useParams()
  const navigate = useNavigate()
  const engine = ENGINES_BY_ID[engineId] ?? null
  const groupDef = engine ? ENGINE_GROUPS[engine.group] : null

  const [lines, setLines] = useState([])
  const [running, setRunning] = useState(false)
  const [clients, setClients] = useState([])
  const [selectedClientId, setSelectedClientId] = useState(null)
  const [target, setTarget] = useState('')
  const [timeout, setTimeoutVal] = useState(120)
  const [toast, setToast] = useState(null)
  const esRef = useRef(null)

  // Load clients
  useEffect(() => {
    apiFetch('/api/clients')
      .then((r) => (r.ok ? r.json() : []))
      .then((d) => { if (Array.isArray(d)) setClients(d) })
      .catch(() => {})
  }, [])

  // Set default target from selected client
  useEffect(() => {
    if (!selectedClientId) return
    const client = clients.find((c) => String(c.id) === String(selectedClientId))
    if (!client) return
    let domains = client.domains
    if (typeof domains === 'string') {
      try { domains = JSON.parse(domains) } catch { domains = [] }
    }
    const first = Array.isArray(domains) ? (domains[0] || '') : ''
    if (first) setTarget(first.startsWith('http') ? first : `https://${first}`)
  }, [selectedClientId, clients])

  const showToast = useCallback((sev, msg) => {
    const id = Date.now()
    setToast({ id, sev, msg })
    setTimeout(() => setToast((t) => (t?.id === id ? null : t)), 5000)
  }, [])

  const handleRun = useCallback(async () => {
    if (!selectedClientId) { showToast('error', 'Select a client first'); return }
    if (engine?.requiresTarget && !target) { showToast('error', 'Enter a target URL'); return }
    setRunning(true)
    setLines([])

    const body = { engine: engineId, client_id: Number(selectedClientId) }
    if (target) body.target = target

    try {
      const r = await apiFetch('/api/command-center/scan', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(body),
      })
      const d = await r.json().catch(() => ({}))
      if (!r.ok) {
        showToast('error', d.detail || d.error || `Scan failed (${r.status})`)
        setRunning(false)
        return
      }
      const jobId = d.job_id || ''
      setLines([`> Job queued: ${jobId || '(no id)'}`, `> Connecting to stream...`])
      if (jobId) {
        const url = apiEventSourceUrl(`/api/poe-scan/stream/${encodeURIComponent(jobId)}`)
        if (esRef.current) esRef.current.close()
        const es = new EventSource(url, { withCredentials: true })
        esRef.current = es
        es.onmessage = (e) => {
          try {
            const data = JSON.parse(e.data || '{}')
            const line = data.message || data.error || ''
            if (line) setLines((prev) => [...prev.slice(-MAX_LINES), `> ${line}`])
            if (data.status === 'completed' || data.status === 'failed') {
              setRunning(false)
              es.close()
            }
          } catch {}
        }
        es.onerror = () => { setRunning(false); es.close() }
      } else {
        setLines((prev) => [...prev, '> (No job stream — check backend logs)'])
        setRunning(false)
      }
    } catch (e) {
      showToast('error', e?.message ?? 'Network error')
      setRunning(false)
    }
  }, [selectedClientId, target, engineId, engine, showToast])

  const handleStop = useCallback(() => {
    if (esRef.current) { esRef.current.close(); esRef.current = null }
    setRunning(false)
    setLines((prev) => [...prev, '> [Stopped by operator]'])
  }, [])

  useEffect(() => () => { if (esRef.current) esRef.current.close() }, [])

  if (!engine) {
    return (
      <div className="min-h-[100dvh] flex flex-col items-center justify-center bg-[#030712] text-slate-300 font-mono p-8">
        <p className="text-red-400 text-lg mb-4">Unknown engine: {engineId}</p>
        <Link to="/engines" className="text-cyan-400 hover:underline">← Engine Matrix</Link>
      </div>
    )
  }

  return (
    <div
      className="min-h-[100dvh] text-slate-100"
      style={{ background: 'radial-gradient(ellipse 100% 70% at 50% 0%, #0f172a 0%, #020617 60%, #000 100%)' }}
    >
      {/* Header */}
      <header className="sticky top-0 z-20 border-b border-white/10 bg-black/50 backdrop-blur-md">
        <div className="max-w-4xl mx-auto px-4 py-3 flex items-center gap-3">
          <Link to="/engines" className="text-white/40 hover:text-white/70 text-xs font-mono transition-colors">
            ← Engine Matrix
          </Link>
          <span className="text-white/20 text-xs">|</span>
          {groupDef && (
            <span
              className="text-[10px] font-mono px-2 py-0.5 rounded uppercase tracking-widest border"
              style={{ color: groupDef.color, borderColor: `${groupDef.color}40`, backgroundColor: `${groupDef.color}10` }}
            >
              {groupDef.label}
            </span>
          )}
          <h1 className="text-sm font-bold text-white">{engine.label}</h1>
        </div>
      </header>

      {/* Toast */}
      {toast && (
        <div
          className={`fixed top-16 right-4 z-50 rounded-xl border px-4 py-3 text-sm font-mono max-w-sm shadow-2xl ${
            toast.sev === 'error'
              ? 'bg-rose-950/90 border-rose-500/40 text-rose-200'
              : 'bg-black/80 border-cyan-500/30 text-cyan-200'
          }`}
        >
          {toast.msg}
        </div>
      )}

      <main className="max-w-4xl mx-auto px-4 py-8 space-y-8">
        {/* Engine meta */}
        <motion.section
          initial={{ opacity: 0, y: 12 }}
          animate={{ opacity: 1, y: 0 }}
          className="rounded-2xl bg-black/40 backdrop-blur-md border border-white/10 p-6 space-y-4"
        >
          <div className="flex flex-wrap items-start justify-between gap-4">
            <div className="space-y-1 min-w-0">
              <div className="flex items-center gap-2">
                <h2 className="text-xl font-bold text-white">{engine.label}</h2>
                <span className="text-[10px] font-mono text-white/30 bg-white/5 px-2 py-0.5 rounded">{engine.id}</span>
              </div>
              <p className="text-sm text-white/60 leading-relaxed">{engine.description}</p>
            </div>
            <MitreCard technique={engine.mitre} />
          </div>
        </motion.section>

        {/* Controls */}
        <motion.section
          initial={{ opacity: 0, y: 12 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ delay: 0.05 }}
          className="rounded-2xl bg-black/40 backdrop-blur-md border border-white/10 p-6 space-y-5"
        >
          <h3 className="text-xs font-mono text-white/50 uppercase tracking-widest">Run Configuration</h3>

          {/* Client selector */}
          <div>
            <label className="block text-[11px] font-mono text-white/50 uppercase tracking-wider mb-1">
              Client
            </label>
            <select
              value={selectedClientId ?? ''}
              onChange={(e) => setSelectedClientId(e.target.value || null)}
              className="bg-black/60 border border-white/10 rounded-lg px-3 py-2 text-sm text-white/80 font-mono focus:outline-none focus:border-cyan-500/40"
            >
              <option value="">— Select client —</option>
              {clients.map((c) => (
                <option key={c.id} value={c.id}>{c.name}</option>
              ))}
            </select>
          </div>

          <ConfigForm
            engine={engine}
            target={target}
            setTarget={setTarget}
            timeout={timeout}
            setTimeout={setTimeoutVal}
            disabled={running}
          />

          <div className="flex items-center gap-3">
            <button
              type="button"
              onClick={handleRun}
              disabled={running}
              className="px-5 py-2 rounded-xl font-mono text-sm font-semibold bg-cyan-500/20 border border-cyan-500/40 text-cyan-300 hover:bg-cyan-500/30 disabled:opacity-50 disabled:cursor-not-allowed transition-all"
            >
              {running ? '⟳ Running…' : '▶ Run Engine'}
            </button>
            {running && (
              <button
                type="button"
                onClick={handleStop}
                className="px-4 py-2 rounded-xl font-mono text-sm border border-red-500/30 text-red-300 hover:bg-red-950/30 transition-all"
              >
                ⏹ Stop
              </button>
            )}
          </div>
        </motion.section>

        {/* Terminal */}
        <motion.section
          initial={{ opacity: 0, y: 12 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ delay: 0.1 }}
          className="rounded-2xl bg-black/40 backdrop-blur-md border border-white/10 p-6 space-y-3"
        >
          <div className="flex items-center justify-between">
            <h3 className="text-xs font-mono text-white/50 uppercase tracking-widest">Live Output</h3>
            {lines.length > 0 && (
              <button
                type="button"
                onClick={() => setLines([])}
                className="text-[10px] font-mono text-white/30 hover:text-white/60 transition-colors"
              >
                Clear
              </button>
            )}
          </div>
          <Terminal lines={lines} engineId={engineId} />
        </motion.section>
      </main>
    </div>
  )
}
