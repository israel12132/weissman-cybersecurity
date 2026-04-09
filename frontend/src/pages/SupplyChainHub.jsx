import React, { useState, useEffect, useCallback } from 'react'
import { motion } from 'framer-motion'
import PageShell from './PageShell'
import { apiFetch } from '../lib/apiBase'

const SUPPLY_ENGINES = [
  { id: 'supply_chain', label: 'Supply Chain Scanner', description: 'Vendor dependency compromise detection' },
  { id: 'cicd_pipeline', label: 'CI/CD Pipeline', description: 'ArgoCD, Jenkins, GitLab CI, Azure DevOps exposure' },
  { id: 'container_registry', label: 'Container Registry', description: 'DockerHub, ECR, /v2/_catalog exposure scan' },
  { id: 'sbom_analyzer', label: 'SBOM Analyzer', description: 'CycloneDX/SPDX lockfile CVE exposure scan' },
  { id: 'typosquatting_monitor', label: 'Typosquatting Monitor', description: 'NPM/PyPI impersonation package detection' },
]

const SEVERITY_COLORS = {
  critical: { bg: 'bg-red-950/30', border: 'border-red-500/30', text: 'text-red-300' },
  high: { bg: 'bg-orange-950/30', border: 'border-orange-500/30', text: 'text-orange-300' },
  medium: { bg: 'bg-amber-950/30', border: 'border-amber-500/30', text: 'text-amber-300' },
  low: { bg: 'bg-blue-950/30', border: 'border-blue-500/30', text: 'text-blue-300' },
  info: { bg: 'bg-white/5', border: 'border-white/10', text: 'text-white/60' },
}

function sevClass(s) {
  return SEVERITY_COLORS[(s || '').toLowerCase()] ?? SEVERITY_COLORS.info
}

function FindingCard({ finding }) {
  const cls = sevClass(finding.severity)
  return (
    <div className={`rounded-xl border p-4 ${cls.bg} ${cls.border} space-y-1`}>
      <div className="flex items-center justify-between gap-2">
        <span className={`text-[10px] font-mono uppercase tracking-widest ${cls.text}`}>
          {finding.severity ?? 'info'}
        </span>
        <span className="text-[10px] font-mono text-white/30">{finding.engine ?? ''}</span>
      </div>
      <p className="text-sm font-medium text-white/90">{finding.title ?? finding.type ?? 'Finding'}</p>
      {finding.target && (
        <p className="text-[11px] font-mono text-white/40 truncate">{finding.target}</p>
      )}
    </div>
  )
}

function EngineRunPanel({ engine, clientId, showToast }) {
  const [running, setRunning] = useState(false)
  const [findings, setFindings] = useState([])
  const [lastRun, setLastRun] = useState(null)

  const handleRun = useCallback(async () => {
    if (!clientId) { showToast('error', 'Select a client first'); return }
    setRunning(true)
    try {
      const r = await apiFetch('/api/command-center/scan', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ engine: engine.id, client_id: Number(clientId) }),
      })
      const d = await r.json().catch(() => ({}))
      if (!r.ok) { showToast('error', d.detail || 'Scan failed'); return }
      showToast('info', `${engine.label}: queued job ${d.job_id ?? ''}`)
      setLastRun(new Date().toLocaleTimeString())
    } catch (e) {
      showToast('error', e?.message ?? 'Network error')
    } finally {
      setRunning(false)
    }
  }, [clientId, engine, showToast])

  return (
    <div className="rounded-2xl bg-black/40 backdrop-blur-md border border-white/10 p-5 space-y-4">
      <div className="flex items-start justify-between gap-3">
        <div>
          <h3 className="text-sm font-semibold text-white">{engine.label}</h3>
          <p className="text-[11px] text-white/40 mt-0.5">{engine.description}</p>
        </div>
        <button
          type="button"
          onClick={handleRun}
          disabled={running || !clientId}
          className="shrink-0 px-3 py-1.5 rounded-lg text-[11px] font-mono uppercase border border-[#84cc16]/30 text-[#84cc16]/70 hover:bg-[#84cc16]/10 disabled:opacity-40 disabled:cursor-not-allowed transition-all"
        >
          {running ? '⟳' : '▶ Run'}
        </button>
      </div>
      {lastRun && (
        <p className="text-[10px] font-mono text-white/30">Last run: {lastRun}</p>
      )}
      {findings.length > 0 && (
        <div className="space-y-2 pt-2 border-t border-white/5">
          {findings.slice(0, 5).map((f, i) => <FindingCard key={i} finding={f} />)}
        </div>
      )}
    </div>
  )
}

export default function SupplyChainHub() {
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
    <PageShell title="Supply Chain Hub" badge="SUPPLY CHAIN" badgeColor="#84cc16" subtitle={`${SUPPLY_ENGINES.length} engines`}>
      {/* Client selector */}
      <div className="flex items-center gap-2 mb-6">
        <span className="text-[11px] font-mono text-white/40">Client:</span>
        <select
          value={selectedClientId ?? ''}
          onChange={(e) => setSelectedClientId(e.target.value || null)}
          className="bg-black/60 border border-white/10 rounded-lg px-3 py-1.5 text-xs text-white/80 font-mono focus:outline-none focus:border-[#84cc16]/40"
        >
          <option value="">— Select client —</option>
          {clients.map((c) => <option key={c.id} value={c.id}>{c.name}</option>)}
        </select>
      </div>

      {/* Toast */}
      {toast && (
        <div className={`fixed top-16 right-4 z-50 rounded-xl border px-4 py-3 text-sm font-mono max-w-sm shadow-2xl ${toast.sev === 'error' ? 'bg-rose-950/90 border-rose-500/40 text-rose-200' : 'bg-black/80 border-[#84cc16]/30 text-[#84cc16]'}`}>
          {toast.msg}
        </div>
      )}

      {!selectedClientId && (
        <div className="rounded-xl border border-amber-500/20 bg-amber-950/20 px-4 py-3 text-sm text-amber-200/80 font-mono mb-6">
          Select a client to enable engine runs.
        </div>
      )}

      <div className="grid grid-cols-1 md:grid-cols-2 xl:grid-cols-3 gap-6">
        {SUPPLY_ENGINES.map((engine) => (
          <motion.div
            key={engine.id}
            initial={{ opacity: 0, y: 8 }}
            animate={{ opacity: 1, y: 0 }}
          >
            <EngineRunPanel engine={engine} clientId={selectedClientId} showToast={showToast} />
          </motion.div>
        ))}
      </div>
    </PageShell>
  )
}
