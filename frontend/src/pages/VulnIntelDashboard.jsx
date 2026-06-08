import React, { useCallback, useEffect, useMemo, useState } from 'react'
import { apiFetch } from '../lib/apiBase'
import FindingDrawer from '../components/ui/FindingDrawer'
import EmptyState from '../components/ui/EmptyState'
import { SkeletonTable } from '../components/ui/Skeleton'

function severityColor(sev) {
  const s = (sev || '').toLowerCase()
  if (s === 'critical') return 'text-rose-400 border-rose-500/40 bg-rose-500/10'
  if (s === 'high') return 'text-orange-400 border-orange-500/40 bg-orange-500/10'
  if (s === 'medium') return 'text-yellow-400 border-yellow-500/40 bg-yellow-500/10'
  if (s === 'low') return 'text-blue-400 border-blue-500/40 bg-blue-500/10'
  return 'text-slate-400 border-slate-600/40 bg-slate-700/10'
}

function StatCard({ label, value, hint }) {
  return (
    <div className="rounded-2xl bg-black/40 border border-white/10 p-5 backdrop-blur-md">
      <div className="text-[10px] font-mono uppercase tracking-widest text-white/40">{label}</div>
      <div className="text-3xl font-bold text-white mt-2">{value}</div>
      {hint && <div className="text-[11px] text-white/45 mt-1">{hint}</div>}
    </div>
  )
}

export default function VulnIntelDashboard() {
  const [findings, setFindings] = useState([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState(null)
  const [filter, setFilter] = useState('')
  const [severityFilter, setSeverityFilter] = useState('all')
  const [total, setTotal] = useState(0)
  const [selected, setSelected] = useState(null)

  const load = useCallback(async () => {
    setLoading(true)
    setError(null)
    const qs = new URLSearchParams({ limit: '1000' })
    if (severityFilter !== 'all') qs.set('severity', severityFilter)
    try {
      const r = await apiFetch(`/api/findings?${qs.toString()}`)
      if (!r.ok) {
        const data = await r.json().catch(() => ({}))
        throw new Error(data.detail || data.error || `HTTP ${r.status}`)
      }
      const data = await r.json()
      const arr = Array.isArray(data) ? data : Array.isArray(data?.findings) ? data.findings : []
      setFindings(arr)
      setTotal(Number(data?.total ?? arr.length))
    } catch (e) {
      setError(e.message || 'Failed to load findings')
    } finally {
      setLoading(false)
    }
  }, [severityFilter])

  useEffect(() => {
    let cancelled = false
    load().catch(() => {})
    return () => {
      cancelled = true
      void cancelled
    }
  }, [load])

  const summary = useMemo(() => {
    const by = { critical: 0, high: 0, medium: 0, low: 0, info: 0 }
    for (const f of findings) {
      const s = (f.severity || 'info').toLowerCase()
      if (by[s] !== undefined) by[s] += 1
    }
    const cves = new Set(findings.map((f) => f.cve || f.cve_id).filter(Boolean))
    return { by, cves: cves.size }
  }, [findings])

  const filtered = useMemo(() => {
    const q = filter.trim().toLowerCase()
    return findings.filter((f) => {
      const sev = (f.severity || '').toLowerCase()
      if (severityFilter !== 'all' && sev !== severityFilter) return false
      if (!q) return true
      const hay = `${f.title || ''} ${f.description || ''} ${f.cve || ''} ${f.source || ''}`.toLowerCase()
      return hay.includes(q)
    })
  }, [findings, filter, severityFilter])

  return (
    <div
      className="min-h-[100dvh] text-slate-100 p-6"
      style={{ background: 'radial-gradient(ellipse 100% 70% at 50% 0%, #0f172a 0%, #020617 60%, #000 100%)' }}
    >
      <header className="mb-6 flex items-end justify-between flex-wrap gap-4">
        <div>
          <h1 className="text-2xl font-bold">Vulnerability Intelligence</h1>
          <p className="text-sm text-white/55 mt-1">
            CVE-correlated findings across all clients. Live data from <code>/api/findings</code>.
          </p>
        </div>
        <div className="text-[11px] font-mono text-white/40">
          {findings.length} shown / {total} total · {summary.cves} distinct CVEs
        </div>
      </header>

      <div className="grid grid-cols-2 md:grid-cols-5 gap-4 mb-6">
        <StatCard label="Critical" value={summary.by.critical} />
        <StatCard label="High" value={summary.by.high} />
        <StatCard label="Medium" value={summary.by.medium} />
        <StatCard label="Low" value={summary.by.low} />
        <StatCard label="Distinct CVEs" value={summary.cves} hint="Unique CVE IDs across findings" />
      </div>

      <div className="rounded-2xl bg-black/40 backdrop-blur-md border border-white/10 p-5 space-y-4">
        <div className="flex items-center justify-between gap-3 flex-wrap">
          <input
            type="search"
            placeholder="Search title, CVE, description, source…"
            value={filter}
            onChange={(e) => setFilter(e.target.value)}
            className="flex-1 min-w-[260px] bg-black/50 border border-white/10 rounded-lg px-3 py-2 text-sm font-mono text-white/85 placeholder-white/30 focus:outline-none focus:border-cyan-500/40"
          />
          <select
            value={severityFilter}
            onChange={(e) => setSeverityFilter(e.target.value)}
            className="bg-black/50 border border-white/10 rounded-lg px-3 py-2 text-sm font-mono text-white/85"
          >
            <option value="all">All severities</option>
            <option value="critical">Critical</option>
            <option value="high">High</option>
            <option value="medium">Medium</option>
            <option value="low">Low</option>
            <option value="info">Info</option>
          </select>
        </div>

        {loading ? (
          <SkeletonTable rows={10} cols={6} />
        ) : error ? (
          <EmptyState
            icon="⚠"
            title="Failed to load findings"
            body={error}
            cta={{ label: 'Retry', onClick: load }}
          />
        ) : filtered.length === 0 ? (
          <EmptyState
            icon="✅"
            title="No findings match"
            body="Nothing matches the current filter. Try widening the severity, clearing the search, or running a scan from the Engine Matrix."
            secondary={{ label: 'Open Engine Matrix', href: '/command-center/engines' }}
          />
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-[12px] font-mono">
              <thead>
                <tr className="text-left text-white/45 border-b border-white/10">
                  <th className="py-2 pe-3">Severity</th>
                  <th className="py-2 pe-3">CVE</th>
                  <th className="py-2 pe-3">Title</th>
                  <th className="py-2 pe-3">Source</th>
                  <th className="py-2 pe-3">Status</th>
                  <th className="py-2 pe-3">Discovered</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-white/5">
                {filtered.slice(0, 200).map((f, i) => (
                  <tr
                    key={f.id || i}
                    onClick={() => setSelected(f)}
                    className="hover:bg-cyan-500/[0.04] cursor-pointer focus-within:bg-cyan-500/[0.04]"
                    tabIndex={0}
                    onKeyDown={(e) => { if (e.key === 'Enter') setSelected(f) }}
                    title="Open evidence drawer"
                  >
                    <td className="py-2 pe-3">
                      <span className={`inline-block px-2 py-0.5 rounded border uppercase tracking-wider text-[10px] ${severityColor(f.severity)}`}>
                        {(f.severity || 'info').toUpperCase()}
                      </span>
                    </td>
                    <td className="py-2 pe-3 text-cyan-400">{f.cve || f.cve_id || '—'}</td>
                    <td className="py-2 pe-3 text-white/80 max-w-md truncate" title={f.title}>
                      {f.title || f.summary || '—'}
                    </td>
                    <td className="py-2 pe-3 text-white/55">{f.source || f.engine || '—'}</td>
                    <td className="py-2 pe-3 text-white/55">{f.status || 'OPEN'}</td>
                    <td className="py-2 pe-3 text-white/40">
                      {f.discovered_at ? new Date(f.discovered_at).toLocaleString() : ''}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
            {filtered.length > 200 && (
              <p className="text-[11px] text-white/35 mt-3">Showing first 200 of {filtered.length} findings — refine filter to narrow.</p>
            )}
          </div>
        )}
      </div>

      <FindingDrawer finding={selected} onClose={() => setSelected(null)} />
    </div>
  )
}
