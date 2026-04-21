import React, { useState, useEffect } from 'react'
import { Link } from 'react-router-dom'
import { useClient } from '../../context/ClientContext'
import { useAuth } from '../../context/AuthContext'
import { formatApiErrorFromBody, formatApiErrorResponse } from '../../lib/apiError.js'
import { apiFetch } from '../../lib/apiBase'

export default function GlobalNexus({ ceoIntegrated = false }) {
  const { isCeo } = useAuth()
  const { clients, clientsError, dismissClientsError, selectedClientId, setSelectedClientId, refreshClients } = useClient()
  const [stats, setStats] = useState({ total_vulnerabilities: 0, security_score: 0, active_scans: 0 })
  const [addName, setAddName] = useState('')
  const [addDomains, setAddDomains] = useState('')
  const [addContactEmail, setAddContactEmail] = useState('')
  const [addIpRanges, setAddIpRanges] = useState('')
  const [addTechStack, setAddTechStack] = useState('')
  const [addAutoDetectTech, setAddAutoDetectTech] = useState(true)
  const [addAwsArn, setAddAwsArn] = useState('')
  const [addAwsExt, setAddAwsExt] = useState('')
  const [addGcp, setAddGcp] = useState('')
  const [addSubmitting, setAddSubmitting] = useState(false)
  const [addMessage, setAddMessage] = useState(null)
  const [deletingId, setDeletingId] = useState(null)

  const handleAddClient = async (e) => {
    if (e) e.preventDefault()
    const name = addName.trim()
    if (!name) {
      setAddMessage({ error: 'Enter client name' })
      return
    }
    setAddMessage(null)
    setAddSubmitting(true)
    try {
      const toJsonArray = (raw) => {
        const t = (raw || '').trim()
        if (!t) return '[]'
        if (t.startsWith('[')) return t
        return JSON.stringify(t.split(/[\s,]+/).filter(Boolean))
      }
      const domains = toJsonArray(addDomains)
      const ip_ranges = toJsonArray(addIpRanges)
      const tech_stack = toJsonArray(addTechStack)
      const payload = {
        name,
        domains,
        ip_ranges,
        tech_stack,
        contact_email: addContactEmail.trim(),
        auto_detect_tech_stack: addAutoDetectTech,
        aws_cross_account_role_arn: addAwsArn.trim(),
        aws_external_id: addAwsExt.trim(),
        gcp_project_id: addGcp.trim(),
      }
      const r = await apiFetch('/api/clients', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(payload),
      })
      const d = await r.json().catch(() => ({}))
      if (r.ok && d.id != null) {
        setAddMessage({ success: true })
        setSelectedClientId(String(d.id))
        setAddName('')
        setAddDomains('')
        setAddContactEmail('')
        setAddIpRanges('')
        setAddTechStack('')
        setAddAutoDetectTech(true)
        setAddAwsArn('')
        setAddAwsExt('')
        setAddGcp('')
        await refreshClients()
        setTimeout(() => setAddMessage(null), 2000)
      } else {
        const errMsg = r.status === 401 ? 'Please log in again' : formatApiErrorFromBody(d, r.status)
        setAddMessage({ error: errMsg })
      }
    } catch (_) {
      setAddMessage({ error: 'Network error' })
    }
    setAddSubmitting(false)
  }

  useEffect(() => {
    let cancelled = false
    const load = async () => {
      try {
        const r = await apiFetch('/api/dashboard/stats')
        if (r.ok && !cancelled) {
          const d = await r.json()
          setStats({
            total_vulnerabilities: d.total_vulnerabilities ?? 0,
            security_score: d.security_score ?? 0,
            active_scans: d.active_scans ? 1 : 0,
          })
        }
      } catch (_) {}
    }
    load()
    const t = setInterval(load, 15000)
    return () => {
      cancelled = true
      clearInterval(t)
    }
  }, [])

  return (
    <aside className="flex flex-col w-full max-w-full lg:w-64 lg:shrink-0 lg:max-w-[16rem] h-auto max-h-[min(42vh,320px)] lg:max-h-none lg:h-full bg-black/40 backdrop-blur-md border-b lg:border-b-0 lg:border-r border-white/10 overflow-y-auto overflow-x-hidden shrink-0">
      {/* Top: Global metrics */}
      <div className="p-4 border-b border-white/10">
        {isCeo && (
          <Link
            to="/"
            className="mb-3 block text-center text-[10px] font-mono uppercase tracking-widest py-2 rounded border border-amber-500/40 text-amber-200/95 hover:bg-amber-950/40"
          >
            {ceoIntegrated ? 'Cockpit · mission control' : 'CEO cockpit home'}
          </Link>
        )}
        <div className="text-[10px] uppercase tracking-[0.2em] text-white/50 mb-3 font-medium">
          Global Nexus
        </div>
        <div className="space-y-3">
          <div className="flex justify-between items-center">
            <span className="text-xs text-[#9ca3af]">Active Threats</span>
            <span className="font-mono text-sm font-semibold text-[#22d3ee] tabular-nums">
              {stats.total_vulnerabilities}
            </span>
          </div>
          <div className="flex justify-between items-center">
            <span className="text-xs text-[#9ca3af]">System Health</span>
            <span
              className="font-mono text-sm font-semibold tabular-nums"
              style={{
                color: stats.security_score >= 70 ? '#4ade80' : stats.security_score >= 40 ? '#fbbf24' : '#f87171',
              }}
            >
              {stats.security_score}%
            </span>
          </div>
          {stats.active_scans > 0 && (
            <div className="flex items-center gap-1.5 text-[10px] text-[#4ade80]">
              <span className="w-1.5 h-1.5 rounded-full bg-[#4ade80] animate-pulse" />
              Scan active
            </div>
          )}
        </div>
      </div>

      {/* Quick navigation to new pages */}
      <div className="px-3 py-3 border-b border-white/10 space-y-1">
        <div className="text-[10px] uppercase tracking-widest text-[#6b7280] px-1 mb-2 font-mono">Quick Nav</div>
        <Link
          id="nav-platform-hub"
          to="/platform-hub"
          className="flex items-center gap-2 px-2 py-1.5 rounded-lg text-[11px] font-mono text-cyan-300/90 hover:bg-cyan-950/40 hover:text-cyan-200 transition-colors font-semibold border border-cyan-500/20"
        >
          <span>⬡</span> Platform Hub
        </Link>
        <Link
          id="nav-engine-matrix"
          to="/engines"
          className="flex items-center gap-2 px-2 py-1.5 rounded-lg text-[11px] font-mono text-cyan-400/80 hover:bg-cyan-950/30 hover:text-cyan-300 transition-colors"
        >
          <span className="text-cyan-500/60">⬡</span> Engine Matrix
        </Link>
        <Link id="nav-threat-emulation" to="/threat-emulation" className="flex items-center gap-2 px-2 py-1.5 rounded-lg text-[11px] font-mono text-red-400/70 hover:bg-red-950/20 hover:text-red-300 transition-colors">
          <span>◈</span> APT Emulation
        </Link>
        <Link id="nav-cloud-tower" to="/cloud" className="flex items-center gap-2 px-2 py-1.5 rounded-lg text-[11px] font-mono text-blue-400/70 hover:bg-blue-950/20 hover:text-blue-300 transition-colors">
          <span>☁</span> Cloud Tower
        </Link>
        <Link id="nav-supply-chain" to="/supply-chain" className="flex items-center gap-2 px-2 py-1.5 rounded-lg text-[11px] font-mono text-lime-400/70 hover:bg-lime-950/20 hover:text-lime-300 transition-colors">
          <span>⛓</span> Supply Chain
        </Link>
        <Link id="nav-network-intel" to="/network" className="flex items-center gap-2 px-2 py-1.5 rounded-lg text-[11px] font-mono text-orange-400/70 hover:bg-orange-950/20 hover:text-orange-300 transition-colors">
          <span>⛢</span> Network Intel
        </Link>
        <Link id="nav-pqc-radar" to="/pqc-radar" className="flex items-center gap-2 px-2 py-1.5 rounded-lg text-[11px] font-mono text-emerald-400/70 hover:bg-emerald-950/20 hover:text-emerald-300 transition-colors">
          <span>🔐</span> PQC Radar
        </Link>
        <Link id="nav-oast" to="/oast" className="flex items-center gap-2 px-2 py-1.5 rounded-lg text-[11px] font-mono text-[#22d3ee]/70 hover:bg-cyan-950/20 hover:text-cyan-300 transition-colors">
          <span>⊂</span> OAST / OOB
        </Link>
        <Link id="nav-digital-twin" to="/digital-twin" className="flex items-center gap-2 px-2 py-1.5 rounded-lg text-[11px] font-mono text-violet-400/70 hover:bg-violet-950/20 hover:text-violet-300 transition-colors">
          <span>⟐</span> Digital Twin
        </Link>
        <Link id="nav-zero-day-radar" to="/zero-day-radar" className="flex items-center gap-2 px-2 py-1.5 rounded-lg text-[11px] font-mono text-rose-400/70 hover:bg-rose-950/20 hover:text-rose-300 transition-colors">
          <span>☢</span> Zero-Day Radar
        </Link>
        <Link to="/findings" id="nav-findings-c2" className="flex items-center gap-2 px-2 py-1.5 rounded-lg text-[11px] font-mono text-amber-400/80 hover:bg-amber-950/30 hover:text-amber-300 transition-colors font-semibold">
          <span>◉</span> Findings C2
        </Link>
        <Link to="/intel-map" id="nav-intel-map" className="flex items-center gap-2 px-2 py-1.5 rounded-lg text-[11px] font-mono text-sky-400/70 hover:bg-sky-950/20 hover:text-sky-300 transition-colors">
          <span>🌐</span> Global Intel Map
        </Link>
        <Link to="/system-core" id="nav-system-core" className="flex items-center gap-2 px-2 py-1.5 rounded-lg text-[11px] font-mono text-slate-400/70 hover:bg-slate-800/40 hover:text-slate-300 transition-colors">
          <span>⚙</span> System Core
        </Link>
        <Link to="/system-status" id="nav-system-status" className="flex items-center gap-2 px-2 py-1.5 rounded-lg text-[11px] font-mono text-emerald-400/70 hover:bg-emerald-950/20 hover:text-emerald-300 transition-colors">
          <span>✓</span> System Status
        </Link>
        {isCeo && (
          <Link to="/admin" id="nav-admin-management" className="flex items-center gap-2 px-2 py-1.5 rounded-lg text-[11px] font-mono text-amber-300/90 hover:bg-amber-950/40 hover:text-amber-200 transition-colors font-semibold border border-amber-500/20 mt-2">
            <span>👤</span> Admin Management
          </Link>
        )}
      </div>

      {/* Body: Client list */}
      <div className="flex-1 overflow-y-auto py-2 min-h-0">
        <div className="text-[10px] uppercase tracking-widest text-[#6b7280] px-4 mb-2 font-mono">
          Clients
        </div>
        {clientsError && (
          <div
            className="mx-4 mb-2 rounded-lg border border-rose-500/40 bg-rose-950/40 px-2 py-2 text-[11px] text-rose-200"
            role="alert"
          >
            <div className="flex justify-between gap-2 items-start">
              <span className="min-w-0 break-words">{clientsError}</span>
              <button
                type="button"
                className="text-rose-400 underline shrink-0 text-[10px]"
                onClick={dismissClientsError}
              >
                Dismiss
              </button>
            </div>
          </div>
        )}
        <ul className="space-y-0.5">
          {clients.length === 0 && !clientsError && (
            <li className="px-4 py-2 text-xs text-white/40">No clients</li>
          )}
          {clients.length === 0 && clientsError && (
            <li className="px-4 py-2 text-xs text-rose-300/90">Client list unavailable.</li>
          )}
          {clients.map((c) => {
            const id = String(c.id)
            const selected = id === String(selectedClientId)
            const isDeleting = deletingId === id
            return (
              <li key={id} className="flex items-center group">
                <button
                  type="button"
                  onClick={() => setSelectedClientId(id)}
                  className={`flex-1 min-w-0 text-left px-4 py-2.5 text-sm font-medium transition-all border-l-2 border-transparent rounded-r ${
                    selected
                      ? 'bg-white/10 border-[#22d3ee] text-white'
                      : 'text-white/70 hover:bg-white/5 hover:text-white/90'
                  }`}
                >
                  <span className="block truncate">{c.name || `Client ${id}`}</span>
                </button>
                <button
                  type="button"
                  onClick={async (e) => {
                    e.stopPropagation()
                    if (isDeleting) return
                    if (!window.confirm(`Delete "${c.name || id}"?`)) return
                    setDeletingId(id)
                    try {
                      const r = await apiFetch(`/api/clients/${id}`, { method: 'DELETE' })
                      if (r.ok || r.status === 204) {
                        if (String(selectedClientId) === id) setSelectedClientId(null)
                        await refreshClients()
                      } else {
                        setAddMessage({ error: await formatApiErrorResponse(r) })
                      }
                    } catch (err) {
                      setAddMessage({ error: err?.message || 'Network error' })
                    }
                    setDeletingId(null)
                  }}
                  disabled={isDeleting}
                  className="shrink-0 p-2 text-[#6b7280] hover:text-[#f87171] opacity-0 group-hover:opacity-100 transition-opacity disabled:opacity-50"
                  aria-label="Delete client"
                >
                  {isDeleting ? (
                    <span className="text-[10px]">…</span>
                  ) : (
                    <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                      <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M19 7l-.867 12.142A2 2 0 0116.138 21H7.862a2 2 0 01-1.995-1.858L5 7m5 4v6m4-6v6m1-10V4a1 1 0 00-1-1h-4a1 1 0 00-1 1v3M4 7h16" />
                    </svg>
                  )}
                </button>
              </li>
            )
          })}
        </ul>
      </div>

      {/* Add Client - button with direct onClick (no form submit) */}
      <div className="border-t border-white/10 p-4 shrink-0 relative z-[100] bg-[#0a0a0a]">
        <div className="text-[10px] uppercase tracking-[0.2em] text-white/50 mb-3 font-medium">
          Add Client
        </div>
        <div className="space-y-2">
          <input
            type="text"
            value={addName}
            onChange={(e) => setAddName(e.target.value)}
            placeholder="Client name *"
            className="w-full px-3 py-2 rounded-xl bg-black/40 border border-white/10 text-white text-sm placeholder-white/40 focus:outline-none focus:border-[#22d3ee]/50"
          />
          <input
            type="text"
            value={addDomains}
            onChange={(e) => setAddDomains(e.target.value)}
            placeholder="Primary domains (required for most engines): a.com, b.com"
            className="w-full px-3 py-2 rounded-xl bg-black/40 border border-white/10 text-white text-sm placeholder-white/40 focus:outline-none focus:border-[#22d3ee]/50"
          />
          <p className="text-[10px] text-white/40 leading-snug">
            OSINT/ASM/leak/BOLA/LLM scans need at least one domain. Tech stack can stay empty — engines infer
            from fingerprints when <span className="text-white/60">auto-detect</span> is on.
          </p>
          <input
            type="email"
            value={addContactEmail}
            onChange={(e) => setAddContactEmail(e.target.value)}
            placeholder="Security contact email (optional)"
            className="w-full px-3 py-2 rounded-xl bg-black/40 border border-white/10 text-white text-sm placeholder-white/40 focus:outline-none focus:border-[#22d3ee]/50"
          />
          <input
            type="text"
            value={addIpRanges}
            onChange={(e) => setAddIpRanges(e.target.value)}
            placeholder="IP ranges (optional): 10.0.0.0/8, 192.168.1.0/24"
            className="w-full px-3 py-2 rounded-xl bg-black/40 border border-white/10 text-white text-sm placeholder-white/40 focus:outline-none focus:border-[#22d3ee]/50"
          />
          <input
            type="text"
            value={addTechStack}
            onChange={(e) => setAddTechStack(e.target.value)}
            placeholder="Known stack hints (optional): react, k8s, nginx or JSON array"
            className="w-full px-3 py-2 rounded-xl bg-black/40 border border-white/10 text-white text-sm placeholder-white/40 focus:outline-none focus:border-[#22d3ee]/50"
          />
          <label className="flex items-center gap-2 text-[11px] text-white/70 cursor-pointer">
            <input
              type="checkbox"
              checked={addAutoDetectTech}
              onChange={(e) => setAddAutoDetectTech(e.target.checked)}
              className="rounded border-white/20"
            />
            Auto-detect tech stack from scan results
          </label>
          <details className="text-[11px] text-white/50">
            <summary className="cursor-pointer text-[#22d3ee]/80 hover:text-[#22d3ee] py-1">
              Cloud integration (optional)
            </summary>
            <div className="space-y-2 pt-2 pl-1 border-l border-white/10 ml-1">
              <input
                type="text"
                value={addAwsArn}
                onChange={(e) => setAddAwsArn(e.target.value)}
                placeholder="AWS cross-account role ARN"
                className="w-full px-3 py-2 rounded-xl bg-black/40 border border-white/10 text-white text-sm placeholder-white/40 focus:outline-none focus:border-[#22d3ee]/50"
              />
              <input
                type="text"
                value={addAwsExt}
                onChange={(e) => setAddAwsExt(e.target.value)}
                placeholder="AWS external ID"
                className="w-full px-3 py-2 rounded-xl bg-black/40 border border-white/10 text-white text-sm placeholder-white/40 focus:outline-none focus:border-[#22d3ee]/50"
              />
              <input
                type="text"
                value={addGcp}
                onChange={(e) => setAddGcp(e.target.value)}
                placeholder="GCP project ID"
                className="w-full px-3 py-2 rounded-xl bg-black/40 border border-white/10 text-white text-sm placeholder-white/40 focus:outline-none focus:border-[#22d3ee]/50"
              />
            </div>
          </details>
          {addMessage?.error && (
            <p id="add-client-error-msg" className="text-xs text-red-400">{addMessage.error}</p>
          )}
          {addMessage?.success && (
            <p id="add-client-success-msg" className="text-xs text-[#4ade80]">Client added.</p>
          )}
          <button
            id="add-client-submit-btn"
            type="button"
            disabled={addSubmitting}
            onClick={() => handleAddClient()}
            className="w-full py-3 rounded-xl text-sm font-medium bg-[#22d3ee]/25 text-[#22d3ee] border-2 border-[#22d3ee]/60 hover:bg-[#22d3ee]/35 hover:border-[#22d3ee] disabled:opacity-50 transition-all cursor-pointer select-none touch-manipulation"
          >
            {addSubmitting ? 'Adding…' : 'Add Client'}
          </button>
        </div>
      </div>
    </aside>
  )
}
