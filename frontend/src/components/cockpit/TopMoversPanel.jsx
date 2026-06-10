import React, { useEffect, useState } from 'react'
import { Link } from 'react-router-dom'
import { apiFetch } from '../../lib/apiBase'

/**
 * Top Movers — three side-by-side ranked lists:
 *   1. Engines by active findings (which detectors are firing hardest)
 *   2. Clients/assets by open critical findings (where the risk concentrates)
 *   3. CVEs by frequency (which exploit IDs we keep tripping on)
 *
 * Inspiration: Snyk "Top issues", Tenable "Top exposures", Wiz "Issues overview".
 * Every row is a `<Link>` deep into the relevant filtered view.
 *
 * Data comes from the same `/api/dashboard/exec-kpis` payload that the KPI strip
 * uses — re-uses the cached fetch instead of firing 3 more requests.
 */

const SEV_COLOR = {
  critical: '#ef4444',
  high:     '#f97316',
  medium:   '#f59e0b',
  low:      '#3b82f6',
  info:     '#6b7280',
}

function Bar({ value, max, color }) {
  const pct = max > 0 ? Math.min(100, Math.round((value / max) * 100)) : 0
  return (
    <div className="relative w-full h-1.5 rounded-full bg-white/5 overflow-hidden mt-1">
      <div
        className="absolute inset-y-0 left-0 rounded-full transition-all duration-500"
        style={{ width: `${pct}%`, background: color, boxShadow: `0 0 6px ${color}80` }}
      />
    </div>
  )
}

function Card({ title, count, children, footer, accent = '#22d3ee' }) {
  return (
    <section
      className="flex flex-col rounded-2xl border border-white/10 bg-black/35 backdrop-blur-md min-w-0"
      aria-label={title}
    >
      <header className="flex items-center justify-between gap-2 px-3 py-2 border-b border-white/[0.06]">
        <div className="min-w-0">
          <h3 className="text-[11px] font-mono uppercase tracking-[0.18em] text-white/75 truncate">
            {title}
          </h3>
          {footer && (
            <p className="text-[10px] font-mono text-white/35 mt-0.5 truncate">{footer}</p>
          )}
        </div>
        <span
          className="text-[10px] font-mono px-2 py-0.5 rounded shrink-0"
          style={{ background: `${accent}18`, color: accent, border: `1px solid ${accent}40` }}
        >
          {count}
        </span>
      </header>
      <div className="p-2 space-y-1 max-h-[260px] overflow-y-auto custom-scroll">
        {children}
      </div>
    </section>
  )
}

function EmptyRow({ label }) {
  return (
    <p className="text-center text-[11px] font-mono text-white/30 py-4">
      {label}
    </p>
  )
}

export default function TopMoversPanel({ className = '' }) {
  const [data, setData] = useState(null)
  const [loading, setLoading] = useState(true)

  useEffect(() => {
    let cancelled = false
    const load = async () => {
      try {
        const r = await apiFetch('/api/dashboard/exec-kpis')
        if (r.ok && !cancelled) setData(await r.json())
      } catch (_) {
        // dashboard tile soft-fails — keep last good payload
      } finally {
        if (!cancelled) setLoading(false)
      }
    }
    load()
    const t = setInterval(load, 30_000)
    return () => { cancelled = true; clearInterval(t) }
  }, [])

  if (loading && !data) {
    return (
      <div className={`grid grid-cols-1 md:grid-cols-3 gap-3 ${className}`}>
        {[0, 1, 2].map((i) => (
          <div key={i} className="h-72 rounded-2xl bg-white/[0.025] border border-white/10 animate-pulse" />
        ))}
      </div>
    )
  }

  const engines = data?.engines_top || []
  const clients = data?.clients_top || []
  const cves    = data?.cves_top || []

  const engineMax = engines.reduce((m, r) => Math.max(m, r.hits || 0), 0)
  const clientMax = clients.reduce((m, r) => Math.max(m, r.total_open || 0), 0)
  const cveMax    = cves.reduce((m, r) => Math.max(m, r.hits || 0), 0)

  return (
    <div className={`grid grid-cols-1 md:grid-cols-3 gap-3 ${className}`}>
      {/* Engines */}
      <Card title="Top engines" count={engines.length} footer="by active findings" accent="#22d3ee">
        {engines.length === 0 ? (
          <EmptyRow label="No engine activity yet" />
        ) : (
          engines.map((e) => (
            <Link
              key={e.id}
              to={`/findings?engine=${encodeURIComponent(e.id)}`}
              className="block px-2 py-1.5 rounded hover:bg-white/[0.04]"
            >
              <div className="flex items-center justify-between gap-2">
                <span className="text-[12px] text-white/80 font-mono truncate">{e.id}</span>
                <span className="flex items-baseline gap-1.5 text-[11px] font-mono shrink-0">
                  {e.critical > 0 && (
                    <span className="text-rose-400" title={`${e.critical} critical`}>
                      ●{e.critical}
                    </span>
                  )}
                  <span className="text-white/75 tabular-nums">{e.hits}</span>
                </span>
              </div>
              <Bar value={e.hits} max={engineMax} color="#22d3ee" />
            </Link>
          ))
        )}
      </Card>

      {/* Clients */}
      <Card title="Top assets at risk" count={clients.length} footer="by open critical findings" accent="#ef4444">
        {clients.length === 0 ? (
          <EmptyRow label="No clients onboarded" />
        ) : (
          clients.map((c) => (
            <Link
              key={c.id}
              to={`/clients/${c.id}`}
              className="block px-2 py-1.5 rounded hover:bg-white/[0.04]"
            >
              <div className="flex items-center justify-between gap-2">
                <span className="text-[12px] text-white/80 truncate font-medium">{c.name}</span>
                <span className="flex items-baseline gap-1.5 text-[11px] font-mono shrink-0">
                  {c.open_critical > 0 && (
                    <span className="text-rose-400" title={`${c.open_critical} critical open`}>
                      ●{c.open_critical}
                    </span>
                  )}
                  <span className="text-white/65 tabular-nums">{c.total_open}</span>
                </span>
              </div>
              <Bar
                value={c.total_open}
                max={clientMax}
                color={c.open_critical > 0 ? '#ef4444' : '#f97316'}
              />
            </Link>
          ))
        )}
      </Card>

      {/* CVEs */}
      <Card title="Top CVEs" count={cves.length} footer="most frequent across assets" accent="#a855f7">
        {cves.length === 0 ? (
          <EmptyRow label="No CVE-correlated findings yet" />
        ) : (
          cves.map((c) => {
            const sev = (c.severity || 'info').toLowerCase()
            const color = SEV_COLOR[sev] || SEV_COLOR.info
            return (
              <a
                key={c.cve}
                href={`https://nvd.nist.gov/vuln/detail/${encodeURIComponent(c.cve)}`}
                target="_blank"
                rel="noopener noreferrer"
                className="block px-2 py-1.5 rounded hover:bg-white/[0.04]"
              >
                <div className="flex items-center justify-between gap-2">
                  <span className="text-[12px] text-cyan-300 font-mono truncate">{c.cve}</span>
                  <span className="text-[11px] font-mono tabular-nums text-white/70 shrink-0">
                    {c.hits}
                  </span>
                </div>
                <Bar value={c.hits} max={cveMax} color={color} />
              </a>
            )
          })
        )}
      </Card>
    </div>
  )
}
