import React, { useEffect, useMemo, useState } from 'react'
import { Link } from 'react-router-dom'
import { TOP_TIER_ENGINE_IDS } from '../lib/topTierEngineProfiles'
import { ENGINES_BY_ID } from '../lib/enginesRegistry'
import { apiEventSourceUrl, apiFetch } from '../lib/apiBase'

function badgeClass(kind) {
  if (kind === 'command_center_engine') return 'text-emerald-300 border-emerald-500/40 bg-emerald-500/10'
  if (kind === 'poe_synthesis_run') return 'text-cyan-300 border-cyan-500/40 bg-cyan-500/10'
  return 'text-rose-300 border-rose-500/40 bg-rose-500/10'
}

export default function TopTierEngineHub() {
  const [audit, setAudit] = useState(null)
  const [loading, setLoading] = useState(true)
  const [clients, setClients] = useState([])
  const [clientId, setClientId] = useState('')
  const [target, setTarget] = useState('')
  const [probeJobId, setProbeJobId] = useState('')
  const [probeRunning, setProbeRunning] = useState(false)
  const [probeSummary, setProbeSummary] = useState('')
  const [probeByEngine, setProbeByEngine] = useState({})

  useEffect(() => {
    let cancelled = false
    async function load() {
      try {
        const r = await apiFetch('/api/engines/top-tier/audit')
        const d = await r.json().catch(() => null)
        if (!cancelled && r.ok) setAudit(d)
      } finally {
        if (!cancelled) setLoading(false)
      }
    }
    load()
    return () => {
      cancelled = true
    }
  }, [])

  useEffect(() => {
    let cancelled = false
    async function loadClients() {
      const r = await apiFetch('/api/clients')
      const d = await r.json().catch(() => [])
      if (!cancelled && r.ok && Array.isArray(d)) setClients(d)
    }
    loadClients()
    return () => {
      cancelled = true
    }
  }, [])

  const auditById = useMemo(() => {
    const rows = Array.isArray(audit?.engines) ? audit.engines : []
    return Object.fromEntries(rows.map((r) => [r.engine_id, r]))
  }, [audit])

  useEffect(() => {
    if (!probeJobId) return undefined
    const url = apiEventSourceUrl(`/api/telemetry/stream?job_id=${encodeURIComponent(probeJobId)}`)
    const es = new EventSource(url, { withCredentials: true })
    es.onmessage = (e) => {
      try {
        const data = JSON.parse(e.data || '{}')
        if (data.job_id !== probeJobId) return
        if (data.engine_id) {
          setProbeByEngine((prev) => ({
            ...prev,
            [data.engine_id]: {
              status: data.probe_status || 'pending',
              message: data.message || '',
              duration_ms: data.duration_ms || 0,
              findings_count: data.findings_count || 0,
            },
          }))
        }
        if (typeof data.message === 'string' && data.message) setProbeSummary(data.message)
        if (data.status === 'completed' || data.status === 'failed') {
          setProbeRunning(false)
          es.close()
        }
      } catch {
        // ignore non-JSON telemetry records
      }
    }
    es.onerror = () => {
      es.close()
    }
    return () => {
      es.close()
    }
  }, [probeJobId])

  useEffect(() => {
    if (!probeRunning || !probeJobId) return undefined
    const iv = setInterval(async () => {
      const r = await apiFetch(`/api/jobs/${encodeURIComponent(probeJobId)}`)
      const d = await r.json().catch(() => null)
      if (!r.ok || !d) return
      if (d.status === 'completed' || d.status === 'failed' || d.status === 'dead') {
        setProbeRunning(false)
      }
      const entries = d?.result?.engines
      if (Array.isArray(entries)) {
        setProbeByEngine((prev) => {
          const next = { ...prev }
          for (const entry of entries) {
            const id = entry?.engine_id
            if (!id) continue
            next[id] = {
              status: entry?.probe_status || 'pending',
              message: entry?.message || '',
              duration_ms: entry?.duration_ms || 0,
              findings_count: entry?.findings_count || 0,
            }
          }
          return next
        })
      }
    }, 2000)
    return () => clearInterval(iv)
  }, [probeJobId, probeRunning])

  async function startHealthProbe() {
    setProbeSummary('Queueing top-tier health probe...')
    setProbeByEngine({})
    const payload = {}
    if (clientId) payload.client_id = Number(clientId)
    if (target.trim()) payload.target = target.trim()
    const r = await apiFetch('/api/engines/top-tier/health-probe', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload),
    })
    const d = await r.json().catch(() => ({}))
    if (!r.ok) {
      setProbeSummary(d.detail || `Probe failed to queue (${r.status})`)
      setProbeRunning(false)
      return
    }
    setProbeJobId(d.job_id || '')
    setProbeRunning(true)
    setProbeSummary(`Probe queued. Job: ${d.job_id || 'unknown'}`)
  }

  function probeBadge(status) {
    if (status === 'pass') return 'text-emerald-300 border-emerald-500/40 bg-emerald-500/10'
    if (status === 'fail') return 'text-rose-300 border-rose-500/40 bg-rose-500/10'
    if (status === 'pending') return 'text-amber-300 border-amber-500/40 bg-amber-500/10'
    return 'text-white/60 border-white/20 bg-white/5'
  }

  return (
    <div className="min-h-[100dvh] text-slate-100" style={{ background: 'radial-gradient(ellipse 130% 80% at 50% 0%, #111827 0%, #020617 55%, #000 100%)' }}>
      <header className="sticky top-0 z-20 border-b border-white/10 bg-black/55 backdrop-blur-md">
        <div className="max-w-7xl mx-auto px-4 py-3 flex items-center justify-between gap-3">
          <div className="flex items-center gap-3">
            <Link to="/engines" className="text-white/40 hover:text-white/70 text-xs font-mono transition-colors">&larr; Engine Matrix</Link>
            <span className="text-white/20 text-xs">|</span>
            <h1 className="text-sm font-bold tracking-tight text-white">Top-Tier Engine Control Hub</h1>
          </div>
          <div className="text-[11px] font-mono text-white/50">
            {loading ? 'Auditing...' : `${audit?.connected_count ?? 0}/${audit?.top_tier_count ?? TOP_TIER_ENGINE_IDS.length} connected`}
          </div>
        </div>
      </header>

      <main className="max-w-7xl mx-auto px-4 py-6 space-y-6">
        <section className="rounded-2xl border border-white/10 bg-black/35 p-5">
          <h2 className="text-sm font-semibold text-white mb-2">Connectivity Reality Check</h2>
          <p className="text-sm text-white/60 leading-relaxed">
            This page audits each Top-Tier engine against catalog registration, canonical resolution, and runtime execution path.
            Green engines are runnable from the Command Center flow.
          </p>
          <div className="mt-4 grid grid-cols-1 md:grid-cols-4 gap-3">
            <select
              value={clientId}
              onChange={(e) => setClientId(e.target.value)}
              className="bg-black/60 border border-white/10 rounded-lg px-3 py-2 text-sm text-white/90"
            >
              <option value="">Client (optional)</option>
              {clients.map((c) => (
                <option key={c.id} value={c.id}>{c.name}</option>
              ))}
            </select>
            <input
              value={target}
              onChange={(e) => setTarget(e.target.value)}
              placeholder="https://target.example"
              className="bg-black/60 border border-white/10 rounded-lg px-3 py-2 text-sm text-white/90 md:col-span-2"
            />
            <button
              type="button"
              onClick={startHealthProbe}
              disabled={probeRunning}
              className="rounded-lg px-3 py-2 text-sm font-mono border border-cyan-500/40 text-cyan-300 hover:bg-cyan-500/10 disabled:opacity-50"
            >
              {probeRunning ? 'Running probe...' : 'Run health probe'}
            </button>
          </div>
          {probeSummary && <div className="mt-3 text-xs font-mono text-white/65">{probeSummary}</div>}
        </section>

        <section className="grid grid-cols-1 md:grid-cols-2 xl:grid-cols-3 gap-4">
          {TOP_TIER_ENGINE_IDS.map((id, idx) => {
            const engine = ENGINES_BY_ID[id]
            const row = auditById[id]
            const path = row?.execution_path || 'unknown'
            const probe = probeByEngine[id] || null
            return (
              <article key={id} className="rounded-xl border border-white/10 bg-black/40 p-4 space-y-3">
                <div className="flex items-center justify-between gap-3">
                  <div>
                    <div className="text-[11px] font-mono text-white/40">Top-Tier #{idx + 1}</div>
                    <h3 className="text-base font-semibold text-white">{engine?.label || id}</h3>
                    <div className="text-[11px] font-mono text-white/40">{id}</div>
                  </div>
                  <span className={`px-2 py-1 rounded border text-[10px] font-mono uppercase tracking-wider ${badgeClass(path)}`}>
                    {path}
                  </span>
                </div>

                <p className="text-sm text-white/55 min-h-[40px]">{engine?.description || 'No description found in registry.'}</p>

                <div className="grid grid-cols-2 gap-2 text-[11px] font-mono text-white/60">
                  <div className="rounded border border-white/10 bg-black/30 p-2">
                    <div className="text-white/35">canonical</div>
                    <div>{row?.canonical_engine || '-'}</div>
                  </div>
                  <div className="rounded border border-white/10 bg-black/30 p-2">
                    <div className="text-white/35">production</div>
                    <div>{row?.is_production_runnable ? 'yes' : 'no'}</div>
                  </div>
                </div>

                <div className="flex items-center gap-2 text-[11px] font-mono">
                  <span className={`px-2 py-1 rounded border uppercase tracking-wider ${probeBadge(probe?.status || 'pending')}`}>
                    probe: {probe?.status || 'pending'}
                  </span>
                  {probe && <span className="text-white/50">{probe.findings_count} findings · {probe.duration_ms}ms</span>}
                </div>
                {probe?.message && <div className="text-[11px] text-white/50">{probe.message}</div>}

                <div className="flex items-center gap-2">
                  <Link
                    to={`/engines/top-tier/${id}`}
                    className="px-3 py-1.5 rounded-lg text-xs font-mono border border-cyan-500/40 text-cyan-300 hover:bg-cyan-500/10 transition-colors"
                  >
                    Open dedicated page
                  </Link>
                  <Link
                    to={`/engines/${id}`}
                    className="px-3 py-1.5 rounded-lg text-xs font-mono border border-white/20 text-white/70 hover:bg-white/5 transition-colors"
                  >
                    Open engine detail
                  </Link>
                </div>
              </article>
            )
          })}
        </section>
      </main>
    </div>
  )
}
