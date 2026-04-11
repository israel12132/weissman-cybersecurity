import React, { useState, useCallback, useEffect } from 'react'
import { Link, useNavigate } from 'react-router-dom'
import { motion, AnimatePresence } from 'framer-motion'
import { apiFetch } from '../lib/apiBase'
import { ENGINES_REGISTRY, ENGINE_GROUP_DEFS } from '../lib/enginesRegistry'

// ─── Helpers ─────────────────────────────────────────────────────────────────

const STAGE_COLORS = {
  'Primary Domain': '#22d3ee',
  'Certificate Transparency': '#8b5cf6',
  'DNS Enumeration': '#3b82f6',
  'Reverse IP Lookup': '#f97316',
  'Web Crawl': '#ec4899',
  'WHOIS Lookup': '#10b981',
  'Email Records': '#f59e0b',
  'Pattern Generation': '#6366f1',
}

function ConfidenceBadge({ confidence }) {
  const color = confidence > 0.8 ? '#4ade80' : confidence > 0.5 ? '#f59e0b' : '#6b7280'
  return (
    <span
      className="px-1.5 py-0.5 rounded text-[10px] font-mono"
      style={{ backgroundColor: `${color}20`, color }}
    >
      {Math.round(confidence * 100)}%
    </span>
  )
}

function LiveBadge({ live, https }) {
  if (!live) {
    return (
      <span className="px-1.5 py-0.5 rounded text-[10px] font-mono bg-red-500/20 text-red-400">
        Offline
      </span>
    )
  }
  return (
    <span className="px-1.5 py-0.5 rounded text-[10px] font-mono bg-green-500/20 text-green-400">
      {https ? '🔒 Live' : 'Live'}
    </span>
  )
}

function StageBadge({ stage }) {
  const color = STAGE_COLORS[stage] ?? '#6b7280'
  return (
    <span
      className="px-2 py-0.5 rounded text-[10px] font-mono border"
      style={{ borderColor: `${color}40`, color, backgroundColor: `${color}10` }}
    >
      {stage}
    </span>
  )
}

// ─── Domain Card ─────────────────────────────────────────────────────────────

function DomainCard({ domain, selected, onSelect, onScanClick }) {
  return (
    <motion.div
      layout
      initial={{ opacity: 0, y: 8 }}
      animate={{ opacity: 1, y: 0 }}
      exit={{ opacity: 0, y: -4 }}
      className={`rounded-xl bg-black/40 backdrop-blur-md border p-4 transition-all duration-200 hover:shadow-[0_0_20px_rgba(0,0,0,0.3)] ${
        selected
          ? 'border-cyan-500/50 bg-cyan-950/20'
          : 'border-white/10 hover:border-white/20'
      }`}
    >
      {/* Header */}
      <div className="flex items-start justify-between gap-2 mb-3">
        <div className="flex items-center gap-2 min-w-0">
          <input
            type="checkbox"
            checked={selected}
            onChange={() => onSelect(domain.domain)}
            className="w-4 h-4 rounded border-white/20 bg-black/40 text-cyan-500 focus:ring-cyan-500/40"
          />
          <span className="text-sm font-semibold text-white truncate">{domain.domain}</span>
        </div>
        <LiveBadge live={domain.live} https={domain.https_available} />
      </div>

      {/* Meta row */}
      <div className="flex flex-wrap items-center gap-2 mb-3">
        <StageBadge stage={domain.stage} />
        <ConfidenceBadge confidence={domain.confidence} />
        {domain.http_status && (
          <span className="text-[10px] font-mono text-white/40">
            HTTP {domain.http_status}
          </span>
        )}
      </div>

      {/* IPs */}
      {domain.ip_addresses && domain.ip_addresses.length > 0 && (
        <div className="mb-2">
          <span className="text-[10px] font-mono text-white/40">IPs: </span>
          <span className="text-[10px] font-mono text-white/60">
            {domain.ip_addresses.slice(0, 3).join(', ')}
            {domain.ip_addresses.length > 3 && ` +${domain.ip_addresses.length - 3} more`}
          </span>
        </div>
      )}

      {/* Title */}
      {domain.title && (
        <p className="text-[11px] text-white/50 leading-relaxed line-clamp-2 mb-3">
          {domain.title}
        </p>
      )}

      {/* Action button */}
      <button
        type="button"
        onClick={() => onScanClick(domain.domain)}
        disabled={!domain.live}
        className="w-full px-3 py-1.5 rounded-lg text-[11px] font-mono uppercase tracking-wide border border-cyan-500/30 text-cyan-300/70 hover:bg-cyan-950/40 hover:text-cyan-200 disabled:opacity-40 disabled:cursor-not-allowed transition-colors"
      >
        Add to Scan
      </button>
    </motion.div>
  )
}

// ─── Stats Bar ───────────────────────────────────────────────────────────────

function StatsBar({ result, selectedCount }) {
  if (!result) return null
  return (
    <div className="flex flex-wrap items-center gap-4 p-4 rounded-xl bg-black/40 border border-white/10">
      <div className="flex flex-col">
        <span className="text-2xl font-bold text-white">{result.total_discovered}</span>
        <span className="text-[10px] font-mono text-white/40 uppercase tracking-wider">Total Discovered</span>
      </div>
      <div className="flex flex-col">
        <span className="text-2xl font-bold text-green-400">{result.live_domains}</span>
        <span className="text-[10px] font-mono text-white/40 uppercase tracking-wider">Live Domains</span>
      </div>
      <div className="flex flex-col">
        <span className="text-2xl font-bold text-cyan-400">{selectedCount}</span>
        <span className="text-[10px] font-mono text-white/40 uppercase tracking-wider">Selected</span>
      </div>
      <div className="flex flex-col">
        <span className="text-lg font-semibold text-white/70">{result.stages_completed?.length || 0}</span>
        <span className="text-[10px] font-mono text-white/40 uppercase tracking-wider">Stages</span>
      </div>
    </div>
  )
}

// ─── Main Page ───────────────────────────────────────────────────────────────

export default function DomainDiscovery() {
  const navigate = useNavigate()
  const [clients, setClients] = useState([])
  const [selectedClientId, setSelectedClientId] = useState(null)
  const [target, setTarget] = useState('')
  const [companyName, setCompanyName] = useState('')
  const [loading, setLoading] = useState(false)
  const [result, setResult] = useState(null)
  const [selectedDomains, setSelectedDomains] = useState(new Set())
  const [filterStage, setFilterStage] = useState('all')
  const [filterLive, setFilterLive] = useState('all')
  const [toast, setToast] = useState(null)
  const [scanAllLoading, setScanAllLoading] = useState(false)

  // Load clients
  useEffect(() => {
    apiFetch('/api/clients')
      .then((r) => (r.ok ? r.json() : []))
      .then((d) => {
        if (Array.isArray(d)) setClients(d)
      })
      .catch(() => {})
  }, [])

  // Set target from selected client
  useEffect(() => {
    if (!selectedClientId) return
    const client = clients.find((c) => String(c.id) === String(selectedClientId))
    if (!client) return
    let domains = client.domains
    if (typeof domains === 'string') {
      try { domains = JSON.parse(domains) } catch { domains = [] }
    }
    const first = Array.isArray(domains) ? (domains[0] || '') : ''
    if (first) setTarget(first)
    if (client.name) setCompanyName(client.name)
  }, [selectedClientId, clients])

  const showToast = useCallback((sev, msg) => {
    const id = Date.now()
    setToast({ id, sev, msg })
    setTimeout(() => setToast((t) => (t?.id === id ? null : t)), 5000)
  }, [])

  const handleDiscover = useCallback(async () => {
    if (!target.trim()) {
      showToast('error', 'Enter a target domain')
      return
    }
    setLoading(true)
    setResult(null)
    setSelectedDomains(new Set())
    
    try {
      const r = await apiFetch('/api/discovery/domains', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          target: target.trim(),
          company_name: companyName.trim() || null,
        }),
      })
      const d = await r.json().catch(() => ({}))
      if (!r.ok) {
        showToast('error', d.detail || `Discovery failed (${r.status})`)
        return
      }
      setResult(d)
      showToast('info', `Discovered ${d.total_discovered} domains (${d.live_domains} live)`)
    } catch (e) {
      showToast('error', e?.message ?? 'Network error')
    } finally {
      setLoading(false)
    }
  }, [target, companyName, showToast])

  const handleSelectDomain = useCallback((domain) => {
    setSelectedDomains((prev) => {
      const next = new Set(prev)
      if (next.has(domain)) {
        next.delete(domain)
      } else {
        next.add(domain)
      }
      return next
    })
  }, [])

  const handleSelectAll = useCallback(() => {
    if (!result?.domains) return
    const filtered = getFilteredDomains()
    setSelectedDomains(new Set(filtered.map((d) => d.domain)))
  }, [result])

  const handleSelectNone = useCallback(() => {
    setSelectedDomains(new Set())
  }, [])

  const handleScanSingle = useCallback(async (domain) => {
    if (!selectedClientId) {
      showToast('error', 'Select a client first')
      return
    }
    navigate(`/engines?target=${encodeURIComponent(domain)}`)
  }, [selectedClientId, navigate, showToast])

  const handleScanAll = useCallback(async () => {
    if (!selectedClientId) {
      showToast('error', 'Select a client first')
      return
    }
    if (selectedDomains.size === 0) {
      showToast('error', 'Select at least one domain')
      return
    }
    setScanAllLoading(true)
    try {
      const r = await apiFetch('/api/scan/discovered-domains', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          client_id: Number(selectedClientId),
          domains: Array.from(selectedDomains),
        }),
      })
      const d = await r.json().catch(() => ({}))
      if (!r.ok) {
        showToast('error', d.detail || `Scan failed (${r.status})`)
        return
      }
      showToast('info', `Scan queued for ${d.domains_count} domains (Job: ${d.job_id})`)
    } catch (e) {
      showToast('error', e?.message ?? 'Network error')
    } finally {
      setScanAllLoading(false)
    }
  }, [selectedClientId, selectedDomains, showToast])

  const getFilteredDomains = useCallback(() => {
    if (!result?.domains) return []
    return result.domains.filter((d) => {
      if (filterStage !== 'all' && d.stage !== filterStage) return false
      if (filterLive === 'live' && !d.live) return false
      if (filterLive === 'offline' && d.live) return false
      return true
    })
  }, [result, filterStage, filterLive])

  const filteredDomains = getFilteredDomains()
  const uniqueStages = result?.domains
    ? [...new Set(result.domains.map((d) => d.stage))]
    : []

  return (
    <div
      className="min-h-[100dvh] text-slate-100"
      style={{
        background: 'radial-gradient(ellipse 120% 80% at 50% 0%, #0f172a 0%, #020617 55%, #000 100%)',
      }}
    >
      {/* Header */}
      <header className="sticky top-0 z-20 border-b border-white/10 bg-black/50 backdrop-blur-md">
        <div className="max-w-screen-2xl mx-auto px-4 py-3 flex flex-wrap items-center justify-between gap-3">
          <div className="flex items-center gap-3">
            <Link to="/" className="text-white/40 hover:text-white/70 text-xs font-mono transition-colors">
              ← Dashboard
            </Link>
            <span className="text-white/20 text-xs">|</span>
            <h1 className="text-sm font-bold tracking-tight text-white">Domain Discovery</h1>
            <span className="text-[10px] font-mono text-white/30 uppercase tracking-widest">
              Auto-Enumerate Company Assets
            </span>
          </div>

          {/* Client selector */}
          <div className="flex items-center gap-2">
            <span className="text-[11px] font-mono text-white/40">Client:</span>
            <select
              value={selectedClientId ?? ''}
              onChange={(e) => setSelectedClientId(e.target.value || null)}
              className="bg-black/60 border border-white/10 rounded-lg px-2 py-1 text-xs text-white/80 font-mono focus:outline-none focus:border-cyan-500/40"
            >
              <option value="">— Select client —</option>
              {clients.map((c) => (
                <option key={c.id} value={c.id}>{c.name}</option>
              ))}
            </select>
          </div>
        </div>
      </header>

      {/* Toast */}
      <AnimatePresence>
        {toast && (
          <motion.div
            key={toast.id}
            initial={{ opacity: 0, y: -8 }}
            animate={{ opacity: 1, y: 0 }}
            exit={{ opacity: 0 }}
            className={`fixed top-16 right-4 z-50 rounded-xl border px-4 py-3 text-sm font-mono max-w-sm shadow-2xl ${
              toast.sev === 'error'
                ? 'bg-rose-950/90 border-rose-500/40 text-rose-200'
                : 'bg-black/80 border-cyan-500/30 text-cyan-200'
            }`}
          >
            {toast.msg}
          </motion.div>
        )}
      </AnimatePresence>

      <main className="max-w-screen-2xl mx-auto px-4 py-6 space-y-6">
        {/* Discovery form */}
        <motion.section
          initial={{ opacity: 0, y: 12 }}
          animate={{ opacity: 1, y: 0 }}
          className="rounded-2xl bg-black/40 backdrop-blur-md border border-white/10 p-6 space-y-4"
        >
          <h2 className="text-xs font-mono text-white/50 uppercase tracking-widest">Discovery Configuration</h2>
          <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
            <div>
              <label className="block text-[11px] font-mono text-white/50 uppercase tracking-wider mb-1">
                Target Domain / URL
              </label>
              <input
                type="text"
                value={target}
                onChange={(e) => setTarget(e.target.value)}
                placeholder="example.com or https://example.com"
                className="w-full bg-black/60 border border-white/10 rounded-lg px-3 py-2 text-sm text-white/90 font-mono placeholder-white/25 focus:outline-none focus:border-cyan-500/40"
              />
            </div>
            <div>
              <label className="block text-[11px] font-mono text-white/50 uppercase tracking-wider mb-1">
                Company Name (optional)
              </label>
              <input
                type="text"
                value={companyName}
                onChange={(e) => setCompanyName(e.target.value)}
                placeholder="Example Corp"
                className="w-full bg-black/60 border border-white/10 rounded-lg px-3 py-2 text-sm text-white/90 font-mono placeholder-white/25 focus:outline-none focus:border-cyan-500/40"
              />
            </div>
            <div className="flex items-end">
              <button
                type="button"
                onClick={handleDiscover}
                disabled={loading || !target.trim()}
                className="w-full px-5 py-2 rounded-xl font-mono text-sm font-semibold bg-cyan-500/20 border border-cyan-500/40 text-cyan-300 hover:bg-cyan-500/30 disabled:opacity-50 disabled:cursor-not-allowed transition-all"
              >
                {loading ? '⟳ Discovering…' : '🔍 Discover Domains'}
              </button>
            </div>
          </div>
          <p className="text-[11px] text-white/40">
            Multi-stage discovery: Certificate Transparency, DNS enumeration, web crawl, email records, and pattern generation.
          </p>
        </motion.section>

        {/* Results */}
        {result && (
          <>
            {/* Stats */}
            <StatsBar result={result} selectedCount={selectedDomains.size} />

            {/* Actions bar */}
            <div className="flex flex-wrap items-center justify-between gap-4">
              {/* Filters */}
              <div className="flex flex-wrap items-center gap-2">
                <select
                  value={filterStage}
                  onChange={(e) => setFilterStage(e.target.value)}
                  className="bg-black/60 border border-white/10 rounded-lg px-2 py-1 text-xs text-white/80 font-mono focus:outline-none focus:border-cyan-500/40"
                >
                  <option value="all">All Stages</option>
                  {uniqueStages.map((s) => (
                    <option key={s} value={s}>{s}</option>
                  ))}
                </select>
                <select
                  value={filterLive}
                  onChange={(e) => setFilterLive(e.target.value)}
                  className="bg-black/60 border border-white/10 rounded-lg px-2 py-1 text-xs text-white/80 font-mono focus:outline-none focus:border-cyan-500/40"
                >
                  <option value="all">All Status</option>
                  <option value="live">Live Only</option>
                  <option value="offline">Offline Only</option>
                </select>
                <span className="text-[10px] font-mono text-white/40">
                  {filteredDomains.length} shown
                </span>
              </div>

              {/* Selection actions */}
              <div className="flex items-center gap-2">
                <button
                  type="button"
                  onClick={handleSelectAll}
                  className="px-3 py-1 rounded-lg text-[11px] font-mono border border-white/10 text-white/50 hover:text-white/80 hover:border-white/20 transition-colors"
                >
                  Select All ({filteredDomains.length})
                </button>
                <button
                  type="button"
                  onClick={handleSelectNone}
                  className="px-3 py-1 rounded-lg text-[11px] font-mono border border-white/10 text-white/50 hover:text-white/80 hover:border-white/20 transition-colors"
                >
                  Deselect All
                </button>
                <button
                  type="button"
                  onClick={handleScanAll}
                  disabled={scanAllLoading || selectedDomains.size === 0 || !selectedClientId}
                  className="px-4 py-1.5 rounded-lg text-[11px] font-mono font-semibold bg-green-500/20 border border-green-500/40 text-green-300 hover:bg-green-500/30 disabled:opacity-50 disabled:cursor-not-allowed transition-all"
                >
                  {scanAllLoading ? '⟳ Scanning…' : `🚀 Scan All Selected (${selectedDomains.size})`}
                </button>
              </div>
            </div>

            {/* Domain grid */}
            <AnimatePresence mode="popLayout">
              <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 xl:grid-cols-4 gap-4">
                {filteredDomains.map((domain) => (
                  <DomainCard
                    key={domain.domain}
                    domain={domain}
                    selected={selectedDomains.has(domain.domain)}
                    onSelect={handleSelectDomain}
                    onScanClick={handleScanSingle}
                  />
                ))}
              </div>
            </AnimatePresence>

            {filteredDomains.length === 0 && (
              <div className="text-center py-12">
                <p className="text-white/40 font-mono text-sm">No domains match the current filters.</p>
              </div>
            )}
          </>
        )}

        {/* Empty state */}
        {!result && !loading && (
          <div className="text-center py-16">
            <div className="text-4xl mb-4">🌐</div>
            <h3 className="text-lg font-semibold text-white/70 mb-2">Auto Domain Discovery</h3>
            <p className="text-white/40 text-sm max-w-md mx-auto">
              Enter a target domain to automatically discover all related domains, subdomains, 
              and assets through multiple reconnaissance stages.
            </p>
          </div>
        )}
      </main>
    </div>
  )
}
