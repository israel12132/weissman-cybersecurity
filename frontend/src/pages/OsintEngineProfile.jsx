import React, { useCallback, useEffect, useMemo, useRef, useState } from 'react'
import { Link } from 'react-router-dom'
import PageShell from './PageShell'
import { apiFetch, apiEventSourceUrl } from '../lib/apiBase'

const MAX_LINES = 500

const OSINT_CAPABILITIES = [
  'Certificate Transparency harvesting (crt.sh) for subdomain intelligence',
  'WHOIS/hostsearch enrichment (HackerTarget) for additional discovered hosts',
  'Canonical target normalization (domain extraction from URL/host input)',
  'De-duplication and wildcard filtering for clean actionable asset output',
  'Structured JSON findings with confidence, severity, and risk impact metadata',
]

const OSINT_OUTPUT_FIELDS = [
  'type',
  'source',
  'asset_type',
  'value',
  'confidence',
  'risk_impact',
  'severity',
]

function Terminal({ lines }) {
  const ref = useRef(null)
  useEffect(() => {
    if (ref.current) ref.current.scrollTop = ref.current.scrollHeight
  }, [lines])

  return (
    <div
      ref={ref}
      className="h-72 overflow-auto rounded-xl bg-black/80 border border-white/5 p-3 font-mono text-[11px] leading-relaxed"
    >
      {lines.length === 0 ? (
        <span className="text-white/20">{`> OSINT idle. Queue a run to start telemetry.`}</span>
      ) : (
        lines.map((line, i) => (
          <div
            key={i}
            className={
              line.includes('[ERROR]')
                ? 'text-red-400'
                : line.toLowerCase().includes('completed')
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

export default function OsintEngineProfile() {
  const [clients, setClients] = useState([])
  const [selectedClientId, setSelectedClientId] = useState('')
  const [target, setTarget] = useState('')
  const [running, setRunning] = useState(false)
  const [lines, setLines] = useState([])
  const [toast, setToast] = useState(null)
  const eventSourceRef = useRef(null)

  useEffect(() => {
    apiFetch('/api/clients')
      .then((r) => (r.ok ? r.json() : []))
      .then((d) => { if (Array.isArray(d)) setClients(d) })
      .catch(() => {})
  }, [])

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

  useEffect(() => () => {
    if (eventSourceRef.current) eventSourceRef.current.close()
  }, [])

  const showToast = useCallback((severity, message) => {
    const id = Date.now()
    setToast({ id, severity, message })
    setTimeout(() => setToast((t) => (t?.id === id ? null : t)), 5000)
  }, [])

  const selectedClientName = useMemo(
    () => clients.find((c) => String(c.id) === String(selectedClientId))?.name ?? 'No client selected',
    [clients, selectedClientId],
  )

  const handleRun = useCallback(async () => {
    if (!selectedClientId) {
      showToast('error', 'Select a client first')
      return
    }
    if (!target.trim()) {
      showToast('error', 'Target domain/URL is required for OSINT')
      return
    }

    setRunning(true)
    setLines([])

    try {
      const r = await apiFetch('/api/command-center/scan', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          engine: 'osint',
          client_id: Number(selectedClientId),
          target: target.trim(),
        }),
      })
      const d = await r.json().catch(() => ({}))
      if (!r.ok) {
        showToast('error', d.detail || d.error || `Scan failed (${r.status})`)
        setRunning(false)
        return
      }

      const jobId = d.job_id || ''
      setLines([`> OSINT queued: ${jobId || '(no id)'}`, '> Connecting to telemetry stream...'])
      if (!jobId) {
        setRunning(false)
        return
      }

      if (eventSourceRef.current) eventSourceRef.current.close()
      const es = new EventSource(apiEventSourceUrl(`/api/telemetry/stream?job_id=${encodeURIComponent(jobId)}`), { withCredentials: true })
      eventSourceRef.current = es

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
      es.onerror = () => {
        setRunning(false)
        es.close()
      }
    } catch (e) {
      showToast('error', e?.message ?? 'Network error')
      setRunning(false)
    }
  }, [selectedClientId, target, showToast])

  return (
    <PageShell
      title="OSINT Engine"
      subtitle="Dedicated profile · first engine in registry"
      badge="RECON"
      badgeColor="#06b6d4"
    >
      {toast && (
        <div
          className={`fixed top-16 right-4 z-50 rounded-xl border px-4 py-3 text-sm font-mono max-w-sm shadow-2xl ${
            toast.severity === 'error'
              ? 'bg-rose-950/90 border-rose-500/40 text-rose-200'
              : 'bg-black/80 border-cyan-500/30 text-cyan-200'
          }`}
        >
          {toast.message}
        </div>
      )}

      <section className="grid xl:grid-cols-[1.3fr_1fr] gap-6">
        <div className="space-y-6">
          <div className="rounded-2xl bg-black/40 border border-white/10 p-6 space-y-3">
            <div className="flex items-center gap-2 flex-wrap">
              <h2 className="text-2xl font-bold text-white">OSINT</h2>
              <span className="text-[10px] font-mono px-2 py-0.5 rounded border border-cyan-500/40 bg-cyan-500/10 text-cyan-300">osint</span>
              <span className="text-[10px] font-mono px-2 py-0.5 rounded border border-white/15 text-white/50">MITRE T1589</span>
            </div>
            <p className="text-sm text-white/70 leading-relaxed">
              Deep external reconnaissance engine for mapping publicly exposed domain assets with validated,
              deduplicated intelligence ready for attack-surface expansion and follow-on scanning workflows.
            </p>
            <div className="flex flex-wrap gap-2 text-[11px] font-mono">
              <Link to="/engines" className="px-2 py-1 rounded border border-white/10 text-white/60 hover:text-cyan-300 hover:border-cyan-500/40 transition-colors">Engine Matrix</Link>
              <Link to="/engine-catalog" className="px-2 py-1 rounded border border-white/10 text-white/60 hover:text-emerald-300 hover:border-emerald-500/40 transition-colors">Client Catalog</Link>
              <Link to="/threat-intel" className="px-2 py-1 rounded border border-white/10 text-white/60 hover:text-purple-300 hover:border-purple-500/40 transition-colors">Threat Intel Hub</Link>
            </div>
          </div>

          <div className="rounded-2xl bg-black/40 border border-white/10 p-6">
            <h3 className="text-xs font-mono text-white/50 uppercase tracking-widest mb-4">What this engine does</h3>
            <ul className="space-y-2 text-sm text-white/70">
              {OSINT_CAPABILITIES.map((capability) => (
                <li key={capability} className="flex items-start gap-2">
                  <span className="text-cyan-300">•</span>
                  <span>{capability}</span>
                </li>
              ))}
            </ul>
          </div>

          <div className="rounded-2xl bg-black/40 border border-white/10 p-6">
            <h3 className="text-xs font-mono text-white/50 uppercase tracking-widest mb-4">Output schema</h3>
            <div className="flex flex-wrap gap-2">
              {OSINT_OUTPUT_FIELDS.map((field) => (
                <span key={field} className="px-2 py-1 rounded border border-white/10 bg-white/5 text-[11px] font-mono text-white/65">
                  {field}
                </span>
              ))}
            </div>
          </div>
        </div>

        <div className="space-y-6">
          <div className="rounded-2xl bg-black/40 border border-white/10 p-6 space-y-4">
            <h3 className="text-xs font-mono text-white/50 uppercase tracking-widest">Run OSINT precisely</h3>
            <div>
              <label className="block text-[11px] font-mono text-white/50 uppercase tracking-wider mb-1">Client</label>
              <select
                value={selectedClientId}
                onChange={(e) => setSelectedClientId(e.target.value)}
                className="w-full bg-black/60 border border-white/10 rounded-lg px-3 py-2 text-sm text-white/90 font-mono focus:outline-none focus:border-cyan-500/40"
              >
                <option value="">— Select client —</option>
                {clients.map((c) => (
                  <option key={c.id} value={c.id}>{c.name}</option>
                ))}
              </select>
              <div className="text-[10px] text-white/35 font-mono mt-1">Active: {selectedClientName}</div>
            </div>
            <div>
              <label className="block text-[11px] font-mono text-white/50 uppercase tracking-wider mb-1">Target URL / Domain</label>
              <input
                type="text"
                value={target}
                onChange={(e) => setTarget(e.target.value)}
                placeholder="https://target.com"
                disabled={running}
                className="w-full bg-black/60 border border-white/10 rounded-lg px-3 py-2 text-sm text-white/90 font-mono placeholder-white/25 focus:outline-none focus:border-cyan-500/40 disabled:opacity-50"
              />
            </div>
            <button
              type="button"
              onClick={handleRun}
              disabled={running}
              className="px-4 py-2 rounded-xl font-mono text-sm font-semibold bg-cyan-500/20 border border-cyan-500/40 text-cyan-300 hover:bg-cyan-500/30 disabled:opacity-50 disabled:cursor-not-allowed transition-all"
            >
              {running ? '⟳ Running OSINT…' : '▶ Run OSINT'}
            </button>
          </div>

          <div className="rounded-2xl bg-black/40 border border-white/10 p-6 space-y-3">
            <h3 className="text-xs font-mono text-white/50 uppercase tracking-widest">Live telemetry</h3>
            <Terminal lines={lines} />
          </div>
        </div>
      </section>
    </PageShell>
  )
}
