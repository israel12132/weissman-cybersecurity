/**
 * Dark Web Monitor — real, customer-scoped intelligence only.
 *
 * Pulls credential / dark-web findings from `/api/findings` (sources: `leak_hunter`,
 * `darkweb_intel`, `dark_web_monitor`, etc.). If no rows exist we render an honest
 * empty state with the exact next steps (run a scan, set HIBP_API_KEY, etc.). No
 * fabricated `acmecorp.com` data.
 */
import React, { useEffect, useMemo, useState } from 'react'
import { Link } from 'react-router-dom'
import PageShell from './PageShell'
import { apiFetch } from '../lib/apiBase'

const SEVERITY_ORDER = { critical: 4, high: 3, medium: 2, low: 1, info: 0 }
const DARK_WEB_SOURCES = new Set([
  'leak_hunter',
  'darkweb_intel',
  'dark_web_monitor',
  'typosquatting_monitor',
])

function severityBadge(sev) {
  const s = (sev || 'info').toLowerCase()
  const map = {
    critical: 'text-rose-300 bg-rose-500/10 border-rose-500/40',
    high: 'text-orange-300 bg-orange-500/10 border-orange-500/40',
    medium: 'text-yellow-300 bg-yellow-500/10 border-yellow-500/40',
    low: 'text-blue-300 bg-blue-500/10 border-blue-500/40',
    info: 'text-slate-300 bg-slate-700/10 border-slate-500/40',
  }
  return `inline-block px-2 py-0.5 rounded text-[10px] font-mono uppercase tracking-wider ${map[s] || map.info}`
}

export default function DarkWebMonitor() {
  const [findings, setFindings] = useState([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState(null)

  useEffect(() => {
    let cancelled = false
    ;(async () => {
      setLoading(true)
      setError(null)
      try {
        const r = await apiFetch('/api/findings?limit=2000')
        if (!r.ok) throw new Error(`HTTP ${r.status}`)
        const d = await r.json()
        if (cancelled) return
        const arr = Array.isArray(d) ? d : Array.isArray(d?.findings) ? d.findings : []
        const filtered = arr.filter((f) => DARK_WEB_SOURCES.has((f.source || f.engine || '').toLowerCase()))
        filtered.sort(
          (a, b) =>
            (SEVERITY_ORDER[(b.severity || '').toLowerCase()] || 0) -
            (SEVERITY_ORDER[(a.severity || '').toLowerCase()] || 0),
        )
        setFindings(filtered)
      } catch (e) {
        if (!cancelled) setError(e.message || 'Failed to load findings')
      } finally {
        if (!cancelled) setLoading(false)
      }
    })()
    return () => { cancelled = true }
  }, [])

  const stats = useMemo(() => {
    const by = { critical: 0, high: 0, medium: 0, low: 0, info: 0 }
    for (const f of findings) {
      const s = (f.severity || 'info').toLowerCase()
      if (by[s] !== undefined) by[s] += 1
    }
    return { ...by, total: findings.length }
  }, [findings])

  return (
    <PageShell title="Dark Web Monitor" subtitle="Credential leaks, typosquats, and dark-web mentions">
      <div className="space-y-6">
        <div className="grid grid-cols-2 md:grid-cols-5 gap-4">
          <StatCard label="Total Hits" value={stats.total} />
          <StatCard label="Critical" value={stats.critical} accent="text-rose-300" />
          <StatCard label="High" value={stats.high} accent="text-orange-300" />
          <StatCard label="Medium" value={stats.medium} accent="text-yellow-300" />
          <StatCard label="Low / Info" value={stats.low + stats.info} accent="text-slate-300" />
        </div>

        {error && (
          <div className="p-4 rounded-xl border border-red-500/30 bg-red-900/20 text-red-300 text-sm">
            Couldn't load findings: {error}.
          </div>
        )}

        <section className="bg-black/40 border border-white/10 rounded-xl p-4">
          <div className="flex items-center justify-between mb-3">
            <h3 className="text-sm font-semibold text-white">Dark-web findings</h3>
            <Link to="/findings" className="text-xs text-cyan-300 hover:text-cyan-200">Open Findings C2 →</Link>
          </div>
          {loading ? (
            <div className="text-sm text-white/40">Loading…</div>
          ) : findings.length === 0 ? (
            <EmptyState />
          ) : (
            <div className="overflow-x-auto">
              <table className="w-full text-[12px] font-mono">
                <thead>
                  <tr className="text-left text-white/45 border-b border-white/10">
                    <th className="py-2 pr-3">Severity</th>
                    <th className="py-2 pr-3">Title</th>
                    <th className="py-2 pr-3">Source</th>
                    <th className="py-2 pr-3">Target</th>
                    <th className="py-2 pr-3">Discovered</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-white/5">
                  {findings.slice(0, 200).map((f) => (
                    <tr key={f.id || f.finding_id} className="hover:bg-white/[0.02]">
                      <td className="py-2 pr-3"><span className={severityBadge(f.severity)}>{(f.severity || 'info').toUpperCase()}</span></td>
                      <td className="py-2 pr-3 text-white/85 max-w-md truncate" title={f.title}>{f.title || '—'}</td>
                      <td className="py-2 pr-3 text-white/55">{f.source || f.engine || '—'}</td>
                      <td className="py-2 pr-3 text-white/55 max-w-xs truncate" title={f.target}>{f.target || '—'}</td>
                      <td className="py-2 pr-3 text-white/40">{f.discovered_at ? new Date(f.discovered_at).toLocaleString() : ''}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </section>
      </div>
    </PageShell>
  )
}

function StatCard({ label, value, accent }) {
  return (
    <div className="rounded-2xl bg-black/40 border border-white/10 p-4">
      <div className="text-[10px] font-mono uppercase tracking-widest text-white/40">{label}</div>
      <div className={`text-3xl font-bold mt-1 ${accent || 'text-white'}`}>{value}</div>
    </div>
  )
}

function EmptyState() {
  return (
    <div className="text-sm text-white/55 space-y-3">
      <div>No dark-web intelligence yet for this tenant.</div>
      <ul className="list-disc pl-5 space-y-1 text-xs text-white/45">
        <li>
          Add a client and{' '}
          <Link to="/clients" className="underline text-cyan-300">run the baseline scan</Link>{' '}
          (Leak Hunter is included in the bundle).
        </li>
        <li>
          For richer breach feeds, set <code className="text-cyan-300">HIBP_API_KEY</code>{' '}
          / <code className="text-cyan-300">OTX_API_KEY</code> in System Configuration; the
          engine is wired but degrades gracefully without keys.
        </li>
        <li>
          Run the <code className="text-cyan-300">darkweb_intel</code> engine from the{' '}
          <Link to="/engines" className="underline text-cyan-300">Engine Matrix</Link>{' '}
          (requires an authorized domain).
        </li>
      </ul>
    </div>
  )
}
