import React, { useState, useEffect, useCallback } from 'react'
import { motion } from 'framer-motion'
import PageShell from './PageShell'
import { apiFetch } from '../lib/apiBase'

const NETWORK_ENGINES = [
  {
    id: 'bgp_dns_hijacking',
    label: 'BGP / DNS Hijacking',
    description: 'Cloudflare DoH vs Google DoH resolver discrepancy + RIPE BGP prefix API cross-check',
    mitre: 'T1584.005',
    color: '#f97316',
  },
  {
    id: 'ipv6_attack',
    label: 'IPv6 Attack Surface',
    description: 'AAAA record enumeration, link-local leak, router advertisement flood surface',
    mitre: 'T1018',
    color: '#f97316',
  },
  {
    id: 'mtls_grpc',
    label: 'mTLS / gRPC',
    description: 'gRPC reflection abuse, missing RequireClientCert enforcement, cert validation gaps',
    mitre: 'T1552',
    color: '#f97316',
  },
  {
    id: 'smb_netbios',
    label: 'SMB / NetBIOS',
    description: 'TCP 445/139/137 exposure with EternalBlue/SMBGhost CVE surface detection',
    mitre: 'T1021.002',
    color: '#f97316',
  },
]

function StatusBadge({ status }) {
  const map = {
    running: { label: 'RUNNING', cls: 'text-[#22d3ee] border-[#22d3ee]/30 bg-[#22d3ee]/10' },
    completed: { label: 'DONE', cls: 'text-[#4ade80] border-[#4ade80]/30 bg-[#4ade80]/10' },
    error: { label: 'ERROR', cls: 'text-red-400 border-red-500/30 bg-red-950/30' },
    idle: { label: 'IDLE', cls: 'text-white/30 border-white/10 bg-white/5' },
  }
  const { label, cls } = map[status] ?? map.idle
  return (
    <span className={`text-[9px] font-mono px-1.5 py-0.5 rounded border uppercase tracking-widest ${cls}`}>
      {label}
    </span>
  )
}

function NetworkEngineCard({ engine, clientId, showToast }) {
  const [status, setStatus] = useState('idle')
  const [findings, setFindings] = useState([])
  const [lastRun, setLastRun] = useState(null)

  const handleRun = useCallback(async () => {
    if (!clientId) { showToast('error', 'Select a client first'); return }
    setStatus('running')
    try {
      const r = await apiFetch('/api/command-center/scan', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ engine: engine.id, client_id: Number(clientId) }),
      })
      const d = await r.json().catch(() => ({}))
      if (!r.ok) {
        setStatus('error')
        showToast('error', d.detail || 'Scan failed')
        return
      }
      showToast('info', `${engine.label}: queued ${d.job_id ?? ''}`)
      setStatus('completed')
      setLastRun(new Date().toLocaleTimeString())
    } catch (e) {
      setStatus('error')
      showToast('error', e?.message ?? 'Network error')
    }
  }, [clientId, engine, showToast])

  return (
    <motion.div
      layout
      initial={{ opacity: 0, y: 8 }}
      animate={{ opacity: 1, y: 0 }}
      className="rounded-2xl bg-black/40 backdrop-blur-md border border-white/10 p-5 space-y-4 hover:border-white/20 transition-all"
    >
      <div className="flex items-start justify-between gap-3">
        <div className="min-w-0">
          <div className="flex items-center gap-2 mb-1">
            <h3 className="text-sm font-semibold text-white">{engine.label}</h3>
            <StatusBadge status={status} />
          </div>
          <span className="text-[9px] font-mono text-white/30 bg-white/5 px-1.5 py-0.5 rounded border border-white/10">
            {engine.mitre}
          </span>
        </div>
        <button
          type="button"
          onClick={handleRun}
          disabled={status === 'running' || !clientId}
          className="shrink-0 px-3 py-1.5 rounded-lg text-[11px] font-mono uppercase border border-[#f97316]/30 text-[#f97316]/70 hover:bg-[#f97316]/10 disabled:opacity-40 disabled:cursor-not-allowed transition-all"
        >
          {status === 'running' ? '⟳' : '▶ Scan'}
        </button>
      </div>

      <p className="text-[11px] text-white/45 leading-relaxed">{engine.description}</p>

      {lastRun && (
        <p className="text-[10px] font-mono text-white/25">Last scan: {lastRun}</p>
      )}

      {findings.length > 0 && (
        <div className="space-y-2 pt-2 border-t border-white/5">
          {findings.slice(0, 3).map((f, i) => (
            <div key={i} className="text-[11px] font-mono text-white/60 bg-white/5 rounded px-2 py-1 truncate">
              {f.title ?? f.type}
            </div>
          ))}
        </div>
      )}
    </motion.div>
  )
}

export default function NetworkIntelligence() {
  const [clients, setClients] = useState([])
  const [selectedClientId, setSelectedClientId] = useState(null)
  const [toast, setToast] = useState(null)

  useEffect(() => {
    apiFetch('/api/clients')
      .then((r) => (r.ok ? r.json() : []))
      .then((d) => { if (Array.isArray(d)) setClients(d) })
      .catch(() => {})
  }, [])

  const showToast = useCallback((sev, msg) => {
    const id = Date.now()
    setToast({ id, sev, msg })
    setTimeout(() => setToast((t) => (t?.id === id ? null : t)), 5000)
  }, [])

  return (
    <PageShell title="Network Intelligence" badge="NETWORK / PROTOCOL" badgeColor="#f97316" subtitle={`${NETWORK_ENGINES.length} engines`}>
      <div className="flex items-center gap-2 mb-6">
        <span className="text-[11px] font-mono text-white/40">Client:</span>
        <select
          value={selectedClientId ?? ''}
          onChange={(e) => setSelectedClientId(e.target.value || null)}
          className="bg-black/60 border border-white/10 rounded-lg px-3 py-1.5 text-xs text-white/80 font-mono focus:outline-none focus:border-[#f97316]/40"
        >
          <option value="">— Select client —</option>
          {clients.map((c) => <option key={c.id} value={c.id}>{c.name}</option>)}
        </select>
      </div>

      {toast && (
        <div className={`fixed top-16 right-4 z-50 rounded-xl border px-4 py-3 text-sm font-mono max-w-sm shadow-2xl ${toast.sev === 'error' ? 'bg-rose-950/90 border-rose-500/40 text-rose-200' : 'bg-black/80 border-[#f97316]/30 text-[#f97316]'}`}>
          {toast.msg}
        </div>
      )}

      {!selectedClientId && (
        <div className="rounded-xl border border-amber-500/20 bg-amber-950/20 px-4 py-3 text-sm text-amber-200/80 font-mono mb-6">
          Select a client to enable scan controls.
        </div>
      )}

      <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
        {NETWORK_ENGINES.map((engine) => (
          <NetworkEngineCard
            key={engine.id}
            engine={engine}
            clientId={selectedClientId}
            showToast={showToast}
          />
        ))}
      </div>
    </PageShell>
  )
}
