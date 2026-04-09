import React, { useState, useEffect, useCallback } from 'react'
import { useParams, useNavigate } from 'react-router-dom'
import { motion, AnimatePresence } from 'framer-motion'
import PageShell from './PageShell'
import { apiFetch } from '../lib/apiBase'

const SIMULATION_SCENARIOS = [
  {
    id: 'xss',
    label: 'XSS Injection',
    mitre: 'T1059.007',
    description: 'Simulates reflected, stored, and DOM-based cross-site scripting attack paths',
    color: '#ef4444',
    risk: 'high',
  },
  {
    id: 'sqli',
    label: 'SQL Injection',
    mitre: 'T1190',
    description: 'Models union-based, blind, time-based, and OOB SQL injection vectors',
    color: '#f97316',
    risk: 'critical',
  },
  {
    id: 'mitm',
    label: 'MITM / TLS Downgrade',
    mitre: 'T1557',
    description: 'Simulates man-in-the-middle via SSL stripping, weak cipher downgrade, HSTS bypass',
    color: '#f59e0b',
    risk: 'high',
  },
  {
    id: 'cors',
    label: 'CORS Misconfiguration',
    mitre: 'T1190',
    description: 'Models cross-origin data exposure via permissive CORS headers and wildcard origins',
    color: '#8b5cf6',
    risk: 'medium',
  },
]

const RISK_COLOR = { critical: '#ef4444', high: '#f97316', medium: '#f59e0b', low: '#22d3ee' }

function ScenarioCard({ scenario, result, onRun, running, disabled }) {
  const riskColor = RISK_COLOR[scenario.risk] ?? '#6b7280'
  return (
    <motion.div
      layout
      initial={{ opacity: 0, y: 8 }}
      animate={{ opacity: 1, y: 0 }}
      className="rounded-2xl bg-black/40 backdrop-blur-md border border-white/10 p-5 space-y-4 hover:border-white/20 transition-all"
      style={result?.vulnerable ? { borderColor: `${riskColor}30` } : {}}
    >
      <div className="flex items-start justify-between gap-3">
        <div className="min-w-0">
          <div className="flex items-center gap-2 mb-1">
            <h3 className="text-sm font-semibold text-white">{scenario.label}</h3>
            <span
              className="text-[9px] font-mono px-1.5 py-0.5 rounded border uppercase tracking-widest"
              style={{ color: riskColor, borderColor: `${riskColor}40`, backgroundColor: `${riskColor}10` }}
            >
              {scenario.risk}
            </span>
          </div>
          <span className="text-[9px] font-mono text-white/30 bg-white/5 px-1.5 py-0.5 rounded border border-white/10">
            {scenario.mitre}
          </span>
        </div>
        <button
          type="button"
          onClick={() => onRun(scenario.id)}
          disabled={disabled || running}
          className="shrink-0 px-3 py-1.5 rounded-lg text-[11px] font-mono uppercase border transition-all disabled:opacity-40 disabled:cursor-not-allowed"
          style={{
            borderColor: `${riskColor}40`,
            color: riskColor,
            backgroundColor: `${riskColor}10`,
          }}
        >
          {running ? '⟳ Simulating' : '▶ Simulate'}
        </button>
      </div>

      <p className="text-[11px] text-white/45 leading-relaxed">{scenario.description}</p>

      {result && (
        <div className="pt-3 border-t border-white/5 space-y-2">
          <div className="flex items-center gap-2">
            <span
              className="w-2 h-2 rounded-full"
              style={{ backgroundColor: result.vulnerable ? riskColor : '#4ade80' }}
            />
            <span className="text-xs font-mono text-white/70">
              {result.vulnerable ? `Vulnerable — ${result.attack_paths ?? 0} attack paths found` : 'Not vulnerable'}
            </span>
          </div>
          {result.details && (
            <p className="text-[10px] font-mono text-white/35 leading-relaxed">{result.details}</p>
          )}
        </div>
      )}
    </motion.div>
  )
}

export default function DigitalTwinSimulator() {
  const { clientId: routeClientId } = useParams()
  const navigate = useNavigate()
  const [clients, setClients] = useState([])
  const [selectedClientId, setSelectedClientId] = useState(routeClientId ?? null)
  const [envProfile, setEnvProfile] = useState(null)
  const [results, setResults] = useState({})
  const [runningId, setRunningId] = useState(null)
  const [toast, setToast] = useState(null)

  useEffect(() => {
    apiFetch('/api/clients')
      .then((r) => (r.ok ? r.json() : []))
      .then((d) => { if (Array.isArray(d)) setClients(d) })
      .catch(() => {})
  }, [])

  // Load environment profile when client changes
  useEffect(() => {
    if (!selectedClientId) { setEnvProfile(null); return }
    const client = clients.find((c) => String(c.id) === String(selectedClientId))
    if (client) {
      setEnvProfile({
        name: client.name,
        domains: (() => {
          let d = client.domains
          if (typeof d === 'string') { try { d = JSON.parse(d) } catch { d = [] } }
          return Array.isArray(d) ? d : []
        })(),
        tech_stack: (() => {
          let t = client.tech_stack
          if (typeof t === 'string') { try { t = JSON.parse(t) } catch { t = [] } }
          return Array.isArray(t) ? t : []
        })(),
      })
    }
  }, [selectedClientId, clients])

  const showToast = useCallback((sev, msg) => {
    const id = Date.now()
    setToast({ id, sev, msg })
    setTimeout(() => setToast((t) => (t?.id === id ? null : t)), 5000)
  }, [])

  const handleSimulate = useCallback(async (scenarioId) => {
    if (!selectedClientId) { showToast('error', 'Select a client first'); return }
    setRunningId(scenarioId)
    try {
      const r = await apiFetch('/api/command-center/scan', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          engine: 'digital_twin',
          client_id: Number(selectedClientId),
          scenario: scenarioId,
        }),
      })
      const d = await r.json().catch(() => ({}))
      if (!r.ok) { showToast('error', d.detail || 'Simulation failed'); return }
      showToast('info', `Digital twin simulation queued: ${d.job_id ?? ''}`)
      setResults((prev) => ({
        ...prev,
        [scenarioId]: { vulnerable: false, attack_paths: 0, details: 'Simulation queued — results will appear when job completes.' },
      }))
    } catch (e) {
      showToast('error', e?.message ?? 'Network error')
    } finally {
      setRunningId(null)
    }
  }, [selectedClientId, showToast])

  const handleRunAll = useCallback(async () => {
    for (const s of SIMULATION_SCENARIOS) {
      await handleSimulate(s.id)
    }
  }, [handleSimulate])

  return (
    <PageShell title="Digital Twin Simulator" badge="APT / SIMULATION" badgeColor="#8b5cf6" subtitle="Environment attack path modeling">
      {/* Controls */}
      <div className="flex flex-wrap items-center justify-between gap-3 mb-8">
        <div className="flex items-center gap-2">
          <span className="text-[11px] font-mono text-white/40">Client:</span>
          <select
            value={selectedClientId ?? ''}
            onChange={(e) => setSelectedClientId(e.target.value || null)}
            className="bg-black/60 border border-white/10 rounded-lg px-3 py-1.5 text-xs text-white/80 font-mono focus:outline-none focus:border-[#8b5cf6]/40"
          >
            <option value="">— Select client —</option>
            {clients.map((c) => <option key={c.id} value={c.id}>{c.name}</option>)}
          </select>
        </div>
        <button
          type="button"
          onClick={handleRunAll}
          disabled={!selectedClientId || !!runningId}
          className="px-4 py-2 rounded-xl font-mono text-sm border border-[#8b5cf6]/40 text-[#8b5cf6] bg-[#8b5cf6]/10 hover:bg-[#8b5cf6]/20 disabled:opacity-40 disabled:cursor-not-allowed transition-all"
        >
          ▶ Run All Simulations
        </button>
      </div>

      {toast && (
        <div className={`fixed top-16 right-4 z-50 rounded-xl border px-4 py-3 text-sm font-mono max-w-sm shadow-2xl ${toast.sev === 'error' ? 'bg-rose-950/90 border-rose-500/40 text-rose-200' : 'bg-black/80 border-[#8b5cf6]/30 text-[#8b5cf6]'}`}>
          {toast.msg}
        </div>
      )}

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-8">
        {/* Environment profile */}
        <div className="space-y-4">
          <h3 className="text-xs font-mono text-white/50 uppercase tracking-widest">Environment Profile</h3>
          <div className="rounded-2xl bg-black/40 backdrop-blur-md border border-white/10 p-5 space-y-4">
            {envProfile ? (
              <>
                <div>
                  <p className="text-[10px] font-mono text-white/40 uppercase tracking-widest mb-1">Client</p>
                  <p className="text-sm font-semibold text-white">{envProfile.name}</p>
                </div>
                {envProfile.domains.length > 0 && (
                  <div>
                    <p className="text-[10px] font-mono text-white/40 uppercase tracking-widest mb-2">Domains</p>
                    <div className="space-y-1">
                      {envProfile.domains.map((d, i) => (
                        <p key={i} className="text-[11px] font-mono text-cyan-300/80 truncate">{d}</p>
                      ))}
                    </div>
                  </div>
                )}
                {envProfile.tech_stack.length > 0 && (
                  <div>
                    <p className="text-[10px] font-mono text-white/40 uppercase tracking-widest mb-2">Tech Stack</p>
                    <div className="flex flex-wrap gap-1">
                      {envProfile.tech_stack.map((t, i) => (
                        <span key={i} className="text-[9px] font-mono px-1.5 py-0.5 rounded bg-white/5 border border-white/10 text-white/50">
                          {t}
                        </span>
                      ))}
                    </div>
                  </div>
                )}
              </>
            ) : (
              <p className="text-[11px] font-mono text-white/25 text-center py-4">
                Select a client to load its environment profile.
              </p>
            )}
          </div>
        </div>

        {/* Simulation scenarios */}
        <div className="lg:col-span-2 space-y-4">
          <h3 className="text-xs font-mono text-white/50 uppercase tracking-widest">Attack Path Simulations</h3>
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            {SIMULATION_SCENARIOS.map((scenario) => (
              <ScenarioCard
                key={scenario.id}
                scenario={scenario}
                result={results[scenario.id] ?? null}
                onRun={handleSimulate}
                running={runningId === scenario.id}
                disabled={!selectedClientId}
              />
            ))}
          </div>
        </div>
      </div>
    </PageShell>
  )
}
