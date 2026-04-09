import React, { useState, useEffect, useCallback } from 'react'
import { useNavigate } from 'react-router-dom'
import { motion } from 'framer-motion'
import PageShell from './PageShell'
import { apiFetch } from '../lib/apiBase'

// ─── APT Group definitions ────────────────────────────────────────────────────

const APT_GROUPS = [
  {
    id: 'lazarus',
    name: 'Lazarus Group',
    alias: 'APT38 / Hidden Cobra',
    nation: 'DPRK',
    techniques: ['T1059', 'T1055', 'T1105', 'T1486'],
    description: 'Nation-state group tied to financial theft and destructive ransomware campaigns.',
    color: '#ef4444',
  },
  {
    id: 'apt28',
    name: 'Fancy Bear',
    alias: 'APT28 / Sofacy',
    nation: 'Russia (GRU)',
    techniques: ['T1566.001', 'T1078', 'T1071.001', 'T1583'],
    description: 'GRU-linked espionage group targeting NATO, governments, and media organizations.',
    color: '#f97316',
  },
  {
    id: 'apt29',
    name: 'Cozy Bear',
    alias: 'APT29 / Midnight Blizzard',
    nation: 'Russia (SVR)',
    techniques: ['T1195.002', 'T1550.001', 'T1560', 'T1021'],
    description: 'SVR-linked group known for SolarWinds supply chain and Microsoft breaches.',
    color: '#f59e0b',
  },
  {
    id: 'apt41',
    name: 'Double Dragon',
    alias: 'APT41 / Winnti',
    nation: 'China (MSS)',
    techniques: ['T1190', 'T1525', 'T1547', 'T1027'],
    description: 'Dual nexus — state-sponsored espionage and financial crime via ransomware.',
    color: '#8b5cf6',
  },
  {
    id: 'sandworm',
    name: 'Sandworm',
    alias: 'Voodoo Bear / Seashell Blizzard',
    nation: 'Russia (GRU Unit 74455)',
    techniques: ['T0855', 'T1485', 'T1071', 'T1210'],
    description: 'Responsible for NotPetya, Ukraine power grid attacks, and Olympic Destroyer.',
    color: '#6366f1',
  },
  {
    id: 'kimsuky',
    name: 'Kimsuky',
    alias: 'Velvet Chollima / Black Banshee',
    nation: 'DPRK (RGB)',
    techniques: ['T1566', 'T1078', 'T1114', 'T1041'],
    description: 'Intelligence collection against South Korea, US, and European targets.',
    color: '#10b981',
  },
  {
    id: 'equation',
    name: 'Equation Group',
    alias: 'NSA TAO (alleged)',
    nation: 'USA (alleged)',
    techniques: ['T1542', 'T1600', 'T1552', 'T1014'],
    description: 'Most technically sophisticated threat actor — Stuxnet, Flame, HDD firmware implants.',
    color: '#22d3ee',
  },
]

function severityBar(value, max = 100) {
  const pct = Math.min(100, Math.max(0, (value / max) * 100))
  const color = pct > 75 ? '#ef4444' : pct > 50 ? '#f97316' : '#22d3ee'
  return { pct, color }
}

function AptCard({ group, result, onRun, running, clientId }) {
  const { pct: blockPct, color: blockColor } = severityBar(result?.blocked_pct ?? 0)
  const { pct: detectPct } = severityBar(result?.detected_pct ?? 0)

  return (
    <motion.div
      layout
      initial={{ opacity: 0, y: 8 }}
      animate={{ opacity: 1, y: 0 }}
      className="rounded-2xl bg-black/40 backdrop-blur-md border border-white/10 p-5 space-y-4 hover:border-white/20 transition-all"
      style={{ borderColor: `${group.color}25` }}
    >
      <div className="flex items-start justify-between gap-3">
        <div className="min-w-0">
          <div className="flex items-center gap-2 mb-1">
            <span
              className="w-2 h-2 rounded-full shrink-0"
              style={{ backgroundColor: group.color, boxShadow: `0 0 5px ${group.color}80` }}
            />
            <h3 className="text-sm font-bold text-white">{group.name}</h3>
          </div>
          <p className="text-[10px] font-mono text-white/40">{group.alias} · {group.nation}</p>
        </div>
        <button
          type="button"
          onClick={() => onRun(group.id)}
          disabled={running || !clientId}
          className="shrink-0 px-3 py-1.5 rounded-lg text-[11px] font-mono uppercase tracking-wide border border-red-500/30 text-red-300/80 hover:bg-red-950/30 disabled:opacity-40 disabled:cursor-not-allowed transition-all"
        >
          {running ? '⟳' : '▶ Emulate'}
        </button>
      </div>

      <p className="text-xs text-white/50 leading-relaxed">{group.description}</p>

      {/* Techniques */}
      <div className="flex flex-wrap gap-1">
        {group.techniques.map((t) => (
          <span key={t} className="text-[9px] font-mono px-1.5 py-0.5 rounded bg-white/5 border border-white/10 text-white/40">
            {t}
          </span>
        ))}
      </div>

      {/* Results */}
      {result ? (
        <div className="space-y-2 pt-2 border-t border-white/5">
          <div className="flex items-center justify-between text-[11px] font-mono">
            <span className="text-white/50">Blocked</span>
            <span style={{ color: blockColor }}>{result.blocked_pct ?? 0}%</span>
          </div>
          <div className="h-1.5 rounded-full bg-white/5 overflow-hidden">
            <div className="h-full rounded-full transition-all" style={{ width: `${blockPct}%`, backgroundColor: blockColor }} />
          </div>
          <div className="flex items-center justify-between text-[11px] font-mono">
            <span className="text-white/50">Detected (not blocked)</span>
            <span className="text-amber-400">{result.detected_pct ?? 0}%</span>
          </div>
          <div className="h-1.5 rounded-full bg-white/5 overflow-hidden">
            <div className="h-full rounded-full bg-amber-500/70 transition-all" style={{ width: `${detectPct}%` }} />
          </div>
          <p className="text-[10px] font-mono text-white/30">
            {result.techniques_tested ?? 0} techniques tested · {result.gaps ?? 0} detection gaps
          </p>
        </div>
      ) : (
        <div className="pt-2 border-t border-white/5">
          <p className="text-[11px] font-mono text-white/25">No emulation data yet — run to generate report.</p>
        </div>
      )}
    </motion.div>
  )
}

export default function ThreatEmulation() {
  const [clients, setClients] = useState([])
  const [selectedClientId, setSelectedClientId] = useState(null)
  const [results, setResults] = useState({})
  const [runningId, setRunningId] = useState(null)
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

  const runEmulation = useCallback(async (groupId) => {
    if (!selectedClientId) { showToast('error', 'Select a client first'); return }
    setRunningId(groupId)
    try {
      const body = {
        engine: 'threat_emulation',
        client_id: Number(selectedClientId),
        apt_group: groupId,
      }
      const r = await apiFetch('/api/command-center/scan', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(body),
      })
      const d = await r.json().catch(() => ({}))
      if (!r.ok) {
        showToast('error', d.detail || d.error || 'Emulation failed')
        return
      }
      showToast('info', `APT emulation queued: job ${d.job_id ?? ''}`)
      // Optimistically set placeholder results
      setResults((prev) => ({
        ...prev,
        [groupId]: { blocked_pct: 0, detected_pct: 0, techniques_tested: 0, gaps: 0, pending: true },
      }))
    } catch (e) {
      showToast('error', e?.message ?? 'Network error')
    } finally {
      setRunningId(null)
    }
  }, [selectedClientId, showToast])

  const runAll = useCallback(async () => {
    for (const group of APT_GROUPS) {
      await runEmulation(group.id)
    }
  }, [runEmulation])

  return (
    <PageShell title="APT Threat Emulation" badge="APT / TOP-TIER" badgeColor="#ef4444" subtitle={`${APT_GROUPS.length} adversary groups`}>
      {/* Client + actions bar */}
      <div className="flex flex-wrap items-center justify-between gap-3 mb-8">
        <div className="flex items-center gap-2">
          <span className="text-[11px] font-mono text-white/40">Target client:</span>
          <select
            value={selectedClientId ?? ''}
            onChange={(e) => setSelectedClientId(e.target.value || null)}
            className="bg-black/60 border border-white/10 rounded-lg px-3 py-1.5 text-xs text-white/80 font-mono focus:outline-none focus:border-cyan-500/40"
          >
            <option value="">— Select —</option>
            {clients.map((c) => <option key={c.id} value={c.id}>{c.name}</option>)}
          </select>
        </div>
        <button
          type="button"
          onClick={runAll}
          disabled={!selectedClientId || !!runningId}
          className="px-4 py-2 rounded-xl font-mono text-sm border border-red-500/30 text-red-300/80 hover:bg-red-950/30 disabled:opacity-40 disabled:cursor-not-allowed transition-all"
        >
          ▶ Run All APT Groups
        </button>
      </div>

      {/* Toast */}
      {toast && (
        <div className={`fixed top-16 right-4 z-50 rounded-xl border px-4 py-3 text-sm font-mono max-w-sm shadow-2xl ${toast.sev === 'error' ? 'bg-rose-950/90 border-rose-500/40 text-rose-200' : 'bg-black/80 border-cyan-500/30 text-cyan-200'}`}>
          {toast.msg}
        </div>
      )}

      {!selectedClientId && (
        <div className="rounded-xl border border-amber-500/20 bg-amber-950/20 px-4 py-3 text-sm text-amber-200/80 font-mono mb-6">
          Select a client to enable emulation runs.
        </div>
      )}

      <div className="grid grid-cols-1 md:grid-cols-2 xl:grid-cols-3 gap-6">
        {APT_GROUPS.map((group) => (
          <AptCard
            key={group.id}
            group={group}
            result={results[group.id] ?? null}
            onRun={runEmulation}
            running={runningId === group.id}
            clientId={selectedClientId}
          />
        ))}
      </div>
    </PageShell>
  )
}
