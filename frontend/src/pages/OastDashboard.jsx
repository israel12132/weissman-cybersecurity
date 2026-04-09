import React, { useState, useEffect, useCallback, useRef } from 'react'
import { motion, AnimatePresence } from 'framer-motion'
import PageShell from './PageShell'
import { apiFetch } from '../lib/apiBase'

const PROBE_TYPES = [
  { id: 'log4shell', label: 'Log4Shell', mitre: 'T1190', description: 'JNDI callback via ${jndi:ldap://oast.pro/...}' },
  { id: 'blind_xss', label: 'Blind XSS', mitre: 'T1059.007', description: 'Out-of-band XSS canary via script src injection' },
  { id: 'blind_xxe', label: 'Blind XXE', mitre: 'T1190', description: 'External entity callback via DTD parameter entity' },
  { id: 'blind_ssrf', label: 'Blind SSRF', mitre: 'T1190', description: 'Out-of-band SSRF callback to confirm OOB reach' },
]

function ProbeCard({ probe, active, onRun, disabled }) {
  return (
    <div className={`rounded-2xl bg-black/40 backdrop-blur-md border p-5 space-y-3 transition-all ${
      active ? 'border-cyan-500/40 shadow-[0_0_20px_rgba(34,211,238,0.1)]' : 'border-white/10 hover:border-white/20'
    }`}>
      <div className="flex items-start justify-between gap-3">
        <div>
          <div className="flex items-center gap-2 mb-1">
            <h3 className="text-sm font-semibold text-white">{probe.label}</h3>
            {active && (
              <span className="relative flex w-2 h-2">
                <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-cyan-400 opacity-75" />
                <span className="relative inline-flex rounded-full h-2 w-2 bg-cyan-400" />
              </span>
            )}
          </div>
          <span className="text-[9px] font-mono text-white/30 bg-white/5 px-1.5 py-0.5 rounded border border-white/10">
            {probe.mitre}
          </span>
        </div>
        <button
          type="button"
          onClick={() => onRun(probe.id)}
          disabled={disabled}
          className="shrink-0 px-3 py-1.5 rounded-lg text-[11px] font-mono uppercase border border-cyan-500/30 text-cyan-300/70 hover:bg-cyan-950/30 disabled:opacity-40 disabled:cursor-not-allowed transition-all"
        >
          {active ? '⟳ Running' : '▶ Probe'}
        </button>
      </div>
      <p className="text-[11px] text-white/45 leading-relaxed">{probe.description}</p>
    </div>
  )
}

function CallbackRow({ cb }) {
  const timeAgo = cb.timestamp
    ? `${Math.round((Date.now() - new Date(cb.timestamp).getTime()) / 1000)}s ago`
    : 'just now'

  return (
    <motion.div
      initial={{ opacity: 0, x: -8 }}
      animate={{ opacity: 1, x: 0 }}
      className="flex items-center gap-3 px-3 py-2 rounded-xl bg-[#22d3ee]/5 border border-[#22d3ee]/20"
    >
      <span className="relative flex w-2 h-2 shrink-0">
        <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-cyan-400 opacity-60" />
        <span className="relative inline-flex rounded-full h-2 w-2 bg-cyan-400" />
      </span>
      <div className="min-w-0 flex-1">
        <p className="text-[11px] font-mono text-cyan-300 truncate">{cb.source_ip ?? '—'}</p>
        <p className="text-[10px] font-mono text-white/30 truncate">{cb.probe_type ?? 'unknown'} · {cb.payload?.slice(0, 40) ?? ''}</p>
      </div>
      <span className="text-[10px] font-mono text-white/25 shrink-0">{timeAgo}</span>
    </motion.div>
  )
}

export default function OastDashboard() {
  const [clients, setClients] = useState([])
  const [selectedClientId, setSelectedClientId] = useState(null)
  const [callbacks, setCallbacks] = useState([])
  const [activeProbes, setActiveProbes] = useState(new Set())
  const [toast, setToast] = useState(null)
  const pollRef = useRef(null)

  useEffect(() => {
    apiFetch('/api/clients')
      .then((r) => (r.ok ? r.json() : []))
      .then((d) => { if (Array.isArray(d)) setClients(d) })
      .catch(() => {})
  }, [])

  // Poll for OOB callbacks
  useEffect(() => {
    const poll = async () => {
      try {
        const r = await apiFetch('/api/oast/callbacks')
        if (r.ok) {
          const d = await r.json()
          if (Array.isArray(d)) setCallbacks(d.slice(-50).reverse())
        }
      } catch {}
    }
    poll()
    pollRef.current = setInterval(poll, 5000)
    return () => clearInterval(pollRef.current)
  }, [])

  const showToast = useCallback((sev, msg) => {
    const id = Date.now()
    setToast({ id, sev, msg })
    setTimeout(() => setToast((t) => (t?.id === id ? null : t)), 5000)
  }, [])

  const handleProbe = useCallback(async (probeId) => {
    if (!selectedClientId) { showToast('error', 'Select a client first'); return }
    setActiveProbes((prev) => new Set([...prev, probeId]))
    try {
      const r = await apiFetch('/api/command-center/scan', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          engine: 'oast_oob',
          client_id: Number(selectedClientId),
          probe_type: probeId,
        }),
      })
      const d = await r.json().catch(() => ({}))
      if (!r.ok) { showToast('error', d.detail || 'Probe failed'); return }
      showToast('info', `OAST probe queued: job ${d.job_id ?? ''}`)
    } catch (e) {
      showToast('error', e?.message ?? 'Network error')
    } finally {
      setTimeout(() => {
        setActiveProbes((prev) => { const s = new Set(prev); s.delete(probeId); return s })
      }, 10000)
    }
  }, [selectedClientId, showToast])

  return (
    <PageShell title="OAST / OOB Dashboard" badge="APT / OOB" badgeColor="#22d3ee" subtitle="Out-of-band callback monitoring">
      {/* Client selector */}
      <div className="flex items-center gap-2 mb-8">
        <span className="text-[11px] font-mono text-white/40">Client:</span>
        <select
          value={selectedClientId ?? ''}
          onChange={(e) => setSelectedClientId(e.target.value || null)}
          className="bg-black/60 border border-white/10 rounded-lg px-3 py-1.5 text-xs text-white/80 font-mono focus:outline-none focus:border-cyan-500/40"
        >
          <option value="">— Select client —</option>
          {clients.map((c) => <option key={c.id} value={c.id}>{c.name}</option>)}
        </select>
      </div>

      {toast && (
        <div className={`fixed top-16 right-4 z-50 rounded-xl border px-4 py-3 text-sm font-mono max-w-sm shadow-2xl ${toast.sev === 'error' ? 'bg-rose-950/90 border-rose-500/40 text-rose-200' : 'bg-black/80 border-cyan-500/30 text-cyan-200'}`}>
          {toast.msg}
        </div>
      )}

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-8">
        {/* Probe controls */}
        <div className="space-y-4">
          <h3 className="text-xs font-mono text-white/50 uppercase tracking-widest">OOB Probes</h3>
          <div className="space-y-4">
            {PROBE_TYPES.map((probe) => (
              <ProbeCard
                key={probe.id}
                probe={probe}
                active={activeProbes.has(probe.id)}
                onRun={handleProbe}
                disabled={!selectedClientId}
              />
            ))}
          </div>
        </div>

        {/* Callback stream */}
        <div className="space-y-4">
          <div className="flex items-center justify-between">
            <h3 className="text-xs font-mono text-white/50 uppercase tracking-widest">Live Callbacks</h3>
            <div className="flex items-center gap-1.5">
              <span className="relative flex w-1.5 h-1.5">
                <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-cyan-400 opacity-60" />
                <span className="relative inline-flex rounded-full h-1.5 w-1.5 bg-cyan-400" />
              </span>
              <span className="text-[10px] font-mono text-white/30">Polling every 5s</span>
            </div>
          </div>

          <div className="rounded-2xl bg-black/40 backdrop-blur-md border border-white/10 p-4 h-[400px] overflow-auto space-y-2">
            <AnimatePresence>
              {callbacks.length === 0 ? (
                <div className="flex items-center justify-center h-full">
                  <p className="text-[11px] font-mono text-white/20">No callbacks received yet. Launch a probe to generate OOB traffic.</p>
                </div>
              ) : (
                callbacks.map((cb, i) => (
                  <CallbackRow key={cb.id ?? i} cb={cb} />
                ))
              )}
            </AnimatePresence>
          </div>
        </div>
      </div>
    </PageShell>
  )
}
