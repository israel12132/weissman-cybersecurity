import React, { useEffect, useMemo, useState } from 'react'
import { Link, useParams } from 'react-router-dom'
import { apiFetch } from '../lib/apiBase'
import { buildSimpleTextPdf, downloadBytes } from '../lib/pdfExport'
import { getTopTierProfile, isTopTierEngine } from '../lib/topTierEngineProfiles'
import {
  CartesianGrid,
  Line,
  LineChart,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
  Bar,
  BarChart,
} from 'recharts'

function JsonBlock({ value }) {
  return (
    <pre className="rounded-xl border border-white/10 bg-black/70 p-3 text-[12px] text-emerald-300 overflow-auto font-mono">
      {JSON.stringify(value, null, 2)}
    </pre>
  )
}

export default function TopTierEngineProfile() {
  const { engineId } = useParams()
  const profile = getTopTierProfile(engineId)
  const [audit, setAudit] = useState(null)
  const [history, setHistory] = useState(null)
  const [clients, setClients] = useState([])
  const [clientId, setClientId] = useState('')
  const [target, setTarget] = useState('')
  const [runState, setRunState] = useState({ running: false, msg: '' })
  const [activeJobId, setActiveJobId] = useState('')
  const [liveJob, setLiveJob] = useState(null)

  useEffect(() => {
    let cancelled = false
    async function loadAudit() {
      const r = await apiFetch('/api/engines/top-tier/audit')
      const d = await r.json().catch(() => null)
      if (!cancelled && r.ok && Array.isArray(d?.engines)) {
        const row = d.engines.find((x) => x.engine_id === engineId) || null
        setAudit(row)
      }
    }
    loadAudit()
    return () => {
      cancelled = true
    }
  }, [engineId])

  useEffect(() => {
    let cancelled = false
    async function loadHistory() {
      const r = await apiFetch(`/api/engines/top-tier/${encodeURIComponent(engineId)}/history?limit=80`)
      const d = await r.json().catch(() => null)
      if (!cancelled && r.ok) setHistory(d)
    }
    loadHistory()
    return () => {
      cancelled = true
    }
  }, [engineId])

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

  const effectivePayload = useMemo(() => {
    const p = { ...(profile?.samplePayload || {}) }
    if (clientId) p.client_id = Number(clientId)
    if (target.trim()) p.target = target.trim()
    return p
  }, [profile, clientId, target])

  const jobs = Array.isArray(history?.jobs) ? history.jobs : []
  const findings = Array.isArray(history?.findings) ? history.findings : []

  const statusChartData = useMemo(() => {
    const tally = { completed: 0, running: 0, failed: 0, pending: 0, dead: 0 }
    for (const j of jobs) {
      const key = String(j?.status || '').toLowerCase()
      if (Object.prototype.hasOwnProperty.call(tally, key)) tally[key] += 1
    }
    return Object.entries(tally).map(([name, value]) => ({ name, value }))
  }, [jobs])

  const findingsTrendData = useMemo(() => {
    return jobs.slice(0, 12).map((j, idx) => ({
      run: `#${jobs.length - idx}`,
      findings: Number(j?.findings_count || 0),
    })).reverse()
  }, [jobs])

  useEffect(() => {
    if (!activeJobId) return undefined
    const iv = setInterval(async () => {
      const r = await apiFetch(`/api/jobs/${encodeURIComponent(activeJobId)}`)
      const d = await r.json().catch(() => null)
      if (!r.ok || !d) return
      setLiveJob(d)
      const status = String(d.status || '').toLowerCase()
      if (status === 'completed' || status === 'failed' || status === 'dead') {
        setRunState((prev) => ({ ...prev, running: false }))
      }
    }, 2000)
    return () => clearInterval(iv)
  }, [activeJobId])

  async function runProbe() {
    if (!profile) return
    setRunState({ running: true, msg: 'Queueing scan job...' })
    try {
      const r = await apiFetch('/api/command-center/scan', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(effectivePayload),
      })
      const d = await r.json().catch(() => ({}))
      if (!r.ok) {
        setRunState({ running: false, msg: d.detail || `Scan failed (${r.status})` })
        return
      }
      setActiveJobId(d.job_id || '')
      setLiveJob(null)
      setRunState({ running: true, msg: `Queued job: ${d.job_id || 'unknown'}` })
    } catch (e) {
      setRunState({ running: false, msg: e?.message || 'Network error' })
    }
  }

  async function exportJson() {
    const r = await apiFetch(`/api/engines/top-tier/${encodeURIComponent(engineId)}/export?limit=120${activeJobId ? `&job_id=${encodeURIComponent(activeJobId)}` : ''}`)
    const d = await r.json().catch(() => null)
    if (!r.ok || !d) {
      setRunState((prev) => ({ ...prev, msg: `Export JSON failed (${r.status})` }))
      return
    }
    const bytes = new TextEncoder().encode(JSON.stringify(d, null, 2))
    downloadBytes(bytes, `top-tier-${engineId}-export.json`, 'application/json')
  }

  function exportPdf() {
    const lines = []
    lines.push(`Top-Tier Engine Profile: ${profile.label} (${profile.id})`)
    lines.push(`Generated: ${new Date().toISOString()}`)
    lines.push(`Execution path: ${audit?.execution_path || '-'}`)
    lines.push(`Canonical: ${audit?.canonical_engine || '-'}`)
    lines.push(`Production runnable: ${audit?.is_production_runnable ? 'yes' : 'no'}`)
    lines.push('')
    lines.push('Mission')
    lines.push(profile.mission)
    lines.push('')
    lines.push('Latest jobs')
    for (const j of jobs.slice(0, 12)) {
      lines.push(`${j?.created_at || '-'} | ${j?.status || '-'} | findings=${j?.findings_count || 0} | ${j?.kind || '-'}`)
    }
    lines.push('')
    lines.push('Findings snapshot')
    for (const f of findings.slice(0, 20)) {
      lines.push(`${f?.discovered_at || '-'} | ${f?.severity || '-'} | ${f?.title || '-'}`)
    }
    if (liveJob?.id) {
      lines.push('')
      lines.push(`Active job evidence: ${liveJob.id}`)
      lines.push(`Status: ${liveJob.status || '-'}`)
      lines.push(`Attempt: ${liveJob.attempt_count || 0}`)
    }
    const bytes = buildSimpleTextPdf(lines)
    downloadBytes(bytes, `top-tier-${engineId}-export.pdf`, 'application/pdf')
  }

  if (!profile || !isTopTierEngine(engineId)) {
    return (
      <div className="min-h-[100dvh] flex flex-col items-center justify-center bg-[#020617] text-slate-300 p-8">
        <div className="text-red-400 mb-3">Unknown Top-Tier engine: {engineId}</div>
        <Link to="/engines/top-tier" className="text-cyan-400 hover:underline">Back to Top-Tier hub</Link>
      </div>
    )
  }

  return (
    <div className="min-h-[100dvh] text-slate-100" style={{ background: 'radial-gradient(ellipse 120% 78% at 50% 0%, #111827 0%, #020617 55%, #000 100%)' }}>
      <header className="sticky top-0 z-20 border-b border-white/10 bg-black/55 backdrop-blur-md">
        <div className="max-w-6xl mx-auto px-4 py-3 flex items-center gap-3">
          <Link to="/engines/top-tier" className="text-white/40 hover:text-white/70 text-xs font-mono transition-colors">&larr; Top-Tier hub</Link>
          <span className="text-white/20 text-xs">|</span>
          <Link to={`/engines/${engineId}`} className="text-cyan-400/80 hover:text-cyan-300 text-xs font-mono transition-colors">Engine detail</Link>
          <span className="text-white/20 text-xs">|</span>
          <h1 className="text-sm font-bold tracking-tight text-white">{profile.label} Strategic Page</h1>
        </div>
      </header>

      <main className="max-w-6xl mx-auto px-4 py-6 space-y-6">
        <section className="rounded-2xl border border-white/10 bg-black/35 p-5 space-y-3">
          <div className="flex flex-wrap items-center gap-2">
            <span className="px-2 py-0.5 rounded border border-white/20 text-[11px] font-mono text-white/70">{profile.id}</span>
            <span className="px-2 py-0.5 rounded border border-cyan-500/30 text-[11px] font-mono text-cyan-300">MITRE {profile.mitre || 'N/A'}</span>
            <span className="px-2 py-0.5 rounded border border-amber-500/30 text-[11px] font-mono text-amber-300">Top-Tier</span>
          </div>
          <p className="text-lg font-semibold text-white">{profile.mission}</p>
          <p className="text-sm text-white/60">{profile.description}</p>
        </section>

        <section className="grid grid-cols-1 lg:grid-cols-3 gap-4">
          <article className="rounded-xl border border-white/10 bg-black/40 p-4 lg:col-span-2">
            <h2 className="text-sm font-semibold text-white mb-2">Deep Intelligence Profile</h2>
            <p className="text-sm text-white/60 mb-3"><span className="text-white/75">Focus:</span> {profile.intelligenceFocus}</p>
            <div className="space-y-2">
              {profile.expectedOutputs.map((item) => (
                <div key={item} className="text-sm text-white/65">- {item}</div>
              ))}
            </div>
          </article>
          <article className="rounded-xl border border-white/10 bg-black/40 p-4">
            <h2 className="text-sm font-semibold text-white mb-2">Reality Status</h2>
            <div className="space-y-2 text-[12px] font-mono text-white/65">
              <div>catalog: {audit?.known_in_catalog ? 'connected' : 'missing'}</div>
              <div>canonical: {audit?.canonical_engine || '-'}</div>
              <div>execution path: {audit?.execution_path || '-'}</div>
              <div>production runnable: {audit?.is_production_runnable ? 'yes' : 'no'}</div>
              <div>jobs tracked: {jobs.length}</div>
              <div>findings tracked: {findings.length}</div>
            </div>
          </article>
        </section>

        <section className="rounded-xl border border-white/10 bg-black/40 p-4 space-y-3">
          <h2 className="text-sm font-semibold text-white">Run This Engine (Live)</h2>
          <div className="grid grid-cols-1 md:grid-cols-3 gap-3">
            <select
              value={clientId}
              onChange={(e) => setClientId(e.target.value)}
              className="bg-black/60 border border-white/10 rounded-lg px-3 py-2 text-sm text-white/90"
            >
              <option value="">Select client (optional)</option>
              {clients.map((c) => (
                <option key={c.id} value={c.id}>{c.name}</option>
              ))}
            </select>
            <input
              value={target}
              onChange={(e) => setTarget(e.target.value)}
              placeholder={profile.requiresTarget ? 'https://target.example' : 'Optional target'}
              className="bg-black/60 border border-white/10 rounded-lg px-3 py-2 text-sm text-white/90"
            />
            <button
              type="button"
              onClick={runProbe}
              disabled={runState.running}
              className="rounded-lg px-3 py-2 text-sm font-mono border border-cyan-500/40 text-cyan-300 hover:bg-cyan-500/10 disabled:opacity-50"
            >
              {runState.running ? 'Running...' : 'Queue Scan'}
            </button>
          </div>
          <div className="flex flex-wrap items-center gap-2">
            <button
              type="button"
              onClick={exportJson}
              className="rounded-lg px-3 py-1.5 text-xs font-mono border border-emerald-500/40 text-emerald-300 hover:bg-emerald-500/10"
            >
              Export JSON
            </button>
            <button
              type="button"
              onClick={exportPdf}
              className="rounded-lg px-3 py-1.5 text-xs font-mono border border-amber-500/40 text-amber-300 hover:bg-amber-500/10"
            >
              Export PDF
            </button>
            {activeJobId && <span className="text-[11px] font-mono text-white/50">job_id: {activeJobId}</span>}
          </div>
          {runState.msg && <div className="text-[12px] font-mono text-white/65">{runState.msg}</div>}
          {liveJob && (
            <div className="rounded-lg border border-white/10 bg-black/40 p-3 text-[12px] font-mono text-white/70">
              <div>Status: {liveJob.status || '-'}</div>
              <div>Attempts: {liveJob.attempt_count || 0}</div>
              <div>Updated: {liveJob.updated_at || '-'}</div>
              {liveJob.last_error && <div className="text-rose-300">Error: {liveJob.last_error}</div>}
              {Array.isArray(liveJob?.result?.findings) && (
                <div>Live findings in result: {liveJob.result.findings.length}</div>
              )}
              {Array.isArray(liveJob?.result?.findings) && liveJob.result.findings.length > 0 && (
                <div className="mt-2 space-y-1">
                  {liveJob.result.findings.slice(0, 8).map((f, idx) => (
                    <div key={idx} className="text-[11px] text-white/60">
                      - {(f?.title || f?.type || 'finding').toString().slice(0, 120)}
                    </div>
                  ))}
                </div>
              )}
            </div>
          )}
        </section>

        <section className="grid grid-cols-1 lg:grid-cols-2 gap-4">
          <article className="rounded-xl border border-white/10 bg-black/40 p-4 h-[280px]">
            <h2 className="text-sm font-semibold text-white mb-2">Job Status Distribution</h2>
            <ResponsiveContainer width="100%" height="90%">
              <BarChart data={statusChartData}>
                <CartesianGrid strokeDasharray="3 3" stroke="#334155" />
                <XAxis dataKey="name" stroke="#94a3b8" />
                <YAxis stroke="#94a3b8" allowDecimals={false} />
                <Tooltip />
                <Bar dataKey="value" fill="#22d3ee" />
              </BarChart>
            </ResponsiveContainer>
          </article>
          <article className="rounded-xl border border-white/10 bg-black/40 p-4 h-[280px]">
            <h2 className="text-sm font-semibold text-white mb-2">Findings Trend by Run</h2>
            <ResponsiveContainer width="100%" height="90%">
              <LineChart data={findingsTrendData}>
                <CartesianGrid strokeDasharray="3 3" stroke="#334155" />
                <XAxis dataKey="run" stroke="#94a3b8" />
                <YAxis stroke="#94a3b8" allowDecimals={false} />
                <Tooltip />
                <Line type="monotone" dataKey="findings" stroke="#4ade80" strokeWidth={2} dot={{ r: 2 }} />
              </LineChart>
            </ResponsiveContainer>
          </article>
        </section>

        <section className="grid grid-cols-1 lg:grid-cols-2 gap-4">
          <article className="rounded-xl border border-white/10 bg-black/40 p-4">
            <h2 className="text-sm font-semibold text-white mb-2">Sample Request Payload</h2>
            <JsonBlock value={effectivePayload} />
          </article>
          <article className="rounded-xl border border-white/10 bg-black/40 p-4">
            <h2 className="text-sm font-semibold text-white mb-2">Operator Notes</h2>
            <div className="space-y-2 text-sm text-white/65">
              <div>- Use this page for per-engine tactical runs and pre-flight validation.</div>
              <div>- Verify execution path is not catalog_only before launch.</div>
              <div>- For tracked jobs, monitor /api/jobs/:job_id and telemetry stream.</div>
              <div>- Cross-check findings in Findings C2 for post-run triage and remediation.</div>
            </div>
          </article>
        </section>

        <section className="rounded-xl border border-white/10 bg-black/40 p-4 space-y-3">
          <h2 className="text-sm font-semibold text-white">Recent Jobs</h2>
          <div className="overflow-auto">
            <table className="w-full text-xs font-mono text-white/70">
              <thead>
                <tr className="text-white/40 border-b border-white/10">
                  <th className="text-left py-2">Job</th>
                  <th className="text-left py-2">Kind</th>
                  <th className="text-left py-2">Status</th>
                  <th className="text-left py-2">Findings</th>
                  <th className="text-left py-2">Created</th>
                </tr>
              </thead>
              <tbody>
                {jobs.slice(0, 20).map((j) => (
                  <tr key={`${j.job_id}-${j.created_at}`} className="border-b border-white/5">
                    <td className="py-2">{j.job_id}</td>
                    <td className="py-2">{j.kind}</td>
                    <td className="py-2">{j.status}{j.probe_status ? ` / ${j.probe_status}` : ''}</td>
                    <td className="py-2">{j.findings_count}</td>
                    <td className="py-2">{j.created_at || '-'}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </section>
      </main>
    </div>
  )
}
