import React, { useState, useEffect, useCallback } from 'react'
import { motion } from 'framer-motion'
import PageShell from './PageShell'
import { apiFetch } from '../lib/apiBase'

const CLOUD_TABS = [
  { id: 'aws', label: 'AWS', engine: 'aws_attack', color: '#f97316', icon: '☁' },
  { id: 'azure', label: 'Azure', engine: 'azure_attack', color: '#3b82f6', icon: '⬡' },
  { id: 'gcp', label: 'GCP', engine: 'gcp_attack', color: '#10b981', icon: '◈' },
  { id: 'k8s', label: 'Kubernetes', engine: 'k8s_container', color: '#8b5cf6', icon: '⎈' },
  { id: 'iac', label: 'IaC', engine: 'iac_misconfig', color: '#06b6d4', icon: '{}' },
  { id: 'serverless', label: 'Serverless', engine: 'serverless_attack', color: '#ec4899', icon: 'λ' },
]

const ENGINE_DESCRIPTIONS = {
  aws_attack: 'IAM privilege escalation, S3 bucket exposure, Lambda event injection, STS token abuse',
  azure_attack: 'Azure AD token abuse, Blob SAS exposure, Function App command injection, RBAC misconfig',
  gcp_attack: 'GCP service account key exposure, Cloud Run abuse, BigQuery public dataset scan',
  k8s_container: 'Kubernetes RBAC misconfig, privileged pod escape, etcd exposure, API server surface',
  iac_misconfig: 'Terraform/CloudFormation/Pulumi misconfiguration scan and drift detection',
  serverless_attack: 'Serverless event injection, function chaining exploitation, cold-start timing',
}

function CloudTab({ tab, active, onClick }) {
  return (
    <button
      type="button"
      onClick={() => onClick(tab.id)}
      className={`flex items-center gap-1.5 px-4 py-2 rounded-xl text-sm font-mono transition-all border ${
        active
          ? 'text-white border'
          : 'text-white/40 border-white/10 hover:border-white/20 hover:text-white/60'
      }`}
      style={active ? { color: tab.color, borderColor: `${tab.color}50`, backgroundColor: `${tab.color}15` } : {}}
    >
      <span>{tab.icon}</span>
      <span>{tab.label}</span>
    </button>
  )
}

function CloudEnginePanel({ tab, clientId, showToast }) {
  const [status, setStatus] = useState('idle')
  const [lastRun, setLastRun] = useState(null)
  const [findings, setFindings] = useState([])

  const handleRun = useCallback(async () => {
    if (!clientId) { showToast('error', 'Select a client first'); return }
    setStatus('running')
    try {
      const r = await apiFetch('/api/command-center/scan', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ engine: tab.engine, client_id: Number(clientId) }),
      })
      const d = await r.json().catch(() => ({}))
      if (!r.ok) { setStatus('error'); showToast('error', d.detail || 'Scan failed'); return }
      showToast('info', `${tab.label}: queued ${d.job_id ?? ''}`)
      setStatus('completed')
      setLastRun(new Date().toLocaleTimeString())
    } catch (e) {
      setStatus('error')
      showToast('error', e?.message ?? 'Network error')
    }
  }, [clientId, tab, showToast])

  const statusColor = { idle: '#374151', running: tab.color, completed: '#4ade80', error: '#ef4444' }[status]

  return (
    <motion.div
      key={tab.id}
      initial={{ opacity: 0, y: 8 }}
      animate={{ opacity: 1, y: 0 }}
      className="space-y-6"
    >
      <div className="rounded-2xl bg-black/40 backdrop-blur-md border border-white/10 p-6">
        <div className="flex items-start justify-between gap-4 mb-4">
          <div>
            <div className="flex items-center gap-3 mb-2">
              <span className="text-3xl" style={{ color: tab.color }}>{tab.icon}</span>
              <div>
                <h2 className="text-lg font-bold text-white">{tab.label} Attack Surface</h2>
                <span className="text-[10px] font-mono text-white/30 uppercase tracking-widest">{tab.engine}</span>
              </div>
            </div>
            <p className="text-sm text-white/50 leading-relaxed">
              {ENGINE_DESCRIPTIONS[tab.engine] ?? 'Cloud infrastructure attack surface scanning'}
            </p>
          </div>
          <div className="flex flex-col items-end gap-2 shrink-0">
            <div className="flex items-center gap-1.5">
              <span
                className="w-2 h-2 rounded-full"
                style={{ backgroundColor: statusColor, boxShadow: status === 'running' ? `0 0 6px ${tab.color}` : 'none' }}
              />
              <span className="text-[10px] font-mono text-white/40 uppercase">{status}</span>
            </div>
            <button
              type="button"
              onClick={handleRun}
              disabled={status === 'running' || !clientId}
              className="px-4 py-2 rounded-xl font-mono text-sm border transition-all disabled:opacity-40 disabled:cursor-not-allowed"
              style={{ borderColor: `${tab.color}40`, color: tab.color, backgroundColor: `${tab.color}10` }}
            >
              {status === 'running' ? '⟳ Scanning…' : '▶ Run Scan'}
            </button>
          </div>
        </div>

        {lastRun && (
          <p className="text-[10px] font-mono text-white/25 mt-2">Last completed: {lastRun}</p>
        )}

        {findings.length === 0 && status !== 'running' && (
          <div className="mt-4 rounded-xl bg-white/5 border border-white/5 p-4 text-center">
            <p className="text-[11px] font-mono text-white/25">
              {status === 'completed'
                ? 'No findings returned — environment appears clean for this engine.'
                : 'Run the engine to populate findings.'}
            </p>
          </div>
        )}

        {findings.length > 0 && (
          <div className="mt-4 space-y-2">
            {findings.map((f, i) => (
              <div key={i} className="rounded-xl bg-white/5 border border-white/10 px-3 py-2 text-xs font-mono text-white/70">
                {f.title ?? f.type}
              </div>
            ))}
          </div>
        )}
      </div>
    </motion.div>
  )
}

export default function CloudControlTower() {
  const [activeTab, setActiveTab] = useState('aws')
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

  const activeTabDef = CLOUD_TABS.find((t) => t.id === activeTab) ?? CLOUD_TABS[0]

  return (
    <PageShell title="Cloud Control Tower" badge="CLOUD / INFRA" badgeColor="#3b82f6" subtitle={`${CLOUD_TABS.length} providers`}>
      {/* Client selector */}
      <div className="flex items-center gap-2 mb-6">
        <span className="text-[11px] font-mono text-white/40">Client:</span>
        <select
          value={selectedClientId ?? ''}
          onChange={(e) => setSelectedClientId(e.target.value || null)}
          className="bg-black/60 border border-white/10 rounded-lg px-3 py-1.5 text-xs text-white/80 font-mono focus:outline-none focus:border-blue-500/40"
        >
          <option value="">— Select client —</option>
          {clients.map((c) => <option key={c.id} value={c.id}>{c.name}</option>)}
        </select>
      </div>

      {toast && (
        <div className={`fixed top-16 right-4 z-50 rounded-xl border px-4 py-3 text-sm font-mono max-w-sm shadow-2xl ${toast.sev === 'error' ? 'bg-rose-950/90 border-rose-500/40 text-rose-200' : 'bg-black/80 border-blue-500/30 text-blue-200'}`}>
          {toast.msg}
        </div>
      )}

      {/* Cloud tabs */}
      <div className="flex flex-wrap gap-2 mb-8">
        {CLOUD_TABS.map((tab) => (
          <CloudTab key={tab.id} tab={tab} active={activeTab === tab.id} onClick={setActiveTab} />
        ))}
      </div>

      {!selectedClientId && (
        <div className="rounded-xl border border-amber-500/20 bg-amber-950/20 px-4 py-3 text-sm text-amber-200/80 font-mono mb-6">
          Select a client to enable scan controls. Cloud engines run without a target URL (use client credential config).
        </div>
      )}

      <CloudEnginePanel
        key={activeTab}
        tab={activeTabDef}
        clientId={selectedClientId}
        showToast={showToast}
      />
    </PageShell>
  )
}
