import React, { useEffect, useMemo, useRef, useState } from 'react'
import { Link } from 'react-router-dom'
import { apiFetch } from '../../lib/apiBase'

/**
 * Executive KPI strip — the always-visible header band at the top of the cockpit.
 *
 * Design inspiration: Wiz "issues" hero, CrowdStrike Falcon overview, Snyk dashboard.
 *
 * What's live (re-fetches every 15s, plus an immediate fetch on mount + on tab focus):
 *   - Critical / High / Medium / Low / Info open findings — with 24h delta arrows
 *   - Security score 0–100
 *   - Total assets + assets with active findings
 *   - Endpoint agents (online / total)
 *   - Job pipeline (running + pending)
 *   - Mean Time To Resolve (MTTR), hours
 *   - "Live" pulse + "updated Ns ago" so users see the data is fresh
 *
 * Every tile is a `<Link>` — clicking drills into the underlying records.
 */
const REFRESH_MS = 15_000

function fmtCount(n) {
  if (n == null) return '—'
  if (n >= 1_000_000) return `${(n / 1_000_000).toFixed(1)}M`
  if (n >= 10_000)   return `${(n / 1000).toFixed(0)}k`
  if (n >= 1_000)    return `${(n / 1000).toFixed(1)}k`
  return String(n)
}

function fmtAgo(unix) {
  if (!unix) return '—'
  const s = Math.max(0, Math.floor(Date.now() / 1000 - unix))
  if (s < 60)   return `${s}s ago`
  if (s < 3600) return `${Math.floor(s / 60)}m ago`
  return `${Math.floor(s / 3600)}h ago`
}

function DeltaArrow({ value }) {
  if (value == null || value === 0) {
    return <span className="text-white/30 text-[10px] font-mono">·</span>
  }
  const up = value > 0
  return (
    <span
      className={`inline-flex items-center gap-0.5 text-[10px] font-mono ${
        up ? 'text-rose-400' : 'text-emerald-400'
      }`}
      title={`${up ? '+' : ''}${value} vs. 24h ago`}
    >
      {up ? '▲' : '▼'} {Math.abs(value)}
    </span>
  )
}

/** Single KPI tile — number + label + small delta / footer line. */
function Tile({ label, value, footer, color = '#22d3ee', to, intensity = 1, ariaLabel }) {
  const inner = (
    <div
      className="group relative flex flex-col justify-between rounded-xl border bg-black/30 backdrop-blur-md px-3 py-2.5 min-w-0 transition-colors hover:bg-black/45"
      style={{
        borderColor: `${color}30`,
        boxShadow: intensity > 1 ? `inset 0 0 0 1px ${color}25` : undefined,
      }}
      role={to ? undefined : 'group'}
      aria-label={ariaLabel || label}
    >
      <div className="flex items-center justify-between gap-1 min-w-0">
        <span
          className="text-[9px] font-mono uppercase tracking-[0.18em] truncate"
          style={{ color: `${color}cc` }}
        >
          {label}
        </span>
        <span
          className="w-1.5 h-1.5 rounded-full opacity-90 shrink-0"
          style={{ background: color, boxShadow: `0 0 6px ${color}80` }}
          aria-hidden="true"
        />
      </div>
      <div className="flex items-baseline gap-1.5 mt-1.5">
        <span
          className="text-2xl font-bold tabular-nums leading-none truncate"
          style={{ color: '#f8fafc' }}
        >
          {value}
        </span>
      </div>
      {footer && (
        <div className="text-[10px] font-mono text-white/45 mt-1.5 truncate">{footer}</div>
      )}
    </div>
  )
  if (to) {
    return (
      <Link to={to} className="block min-w-0 focus:outline-none focus:ring-2 focus:ring-cyan-400/40 rounded-xl">
        {inner}
      </Link>
    )
  }
  return inner
}

/** Compact 24-point sparkline (inline SVG, no external dep). */
function MiniSpark({ values, color = '#22d3ee', height = 28 }) {
  const path = useMemo(() => {
    if (!values || values.length === 0) return ''
    const max = Math.max(1, ...values)
    const w = 80
    const h = height
    const step = w / Math.max(1, values.length - 1)
    return values
      .map((v, i) => {
        const x = (i * step).toFixed(1)
        const y = (h - (v / max) * (h - 2) - 1).toFixed(1)
        return `${i === 0 ? 'M' : 'L'}${x},${y}`
      })
      .join(' ')
  }, [values, height])
  return (
    <svg width="80" height={height} viewBox={`0 0 80 ${height}`} aria-hidden="true">
      <path d={path} fill="none" stroke={color} strokeWidth="1.4" strokeLinecap="round" strokeLinejoin="round" />
    </svg>
  )
}

export default function ExecKpiStrip() {
  const [kpis, setKpis] = useState(null)
  const [loading, setLoading] = useState(true)
  const [err, setErr] = useState(null)
  const [now, setNow] = useState(Date.now())
  const cancelRef = useRef(false)

  const refresh = async () => {
    try {
      const r = await apiFetch('/api/dashboard/exec-kpis')
      if (!r.ok) throw new Error(`HTTP ${r.status}`)
      const d = await r.json()
      if (!cancelRef.current) {
        setKpis(d)
        setErr(null)
      }
    } catch (e) {
      if (!cancelRef.current) setErr(e?.message || 'fetch failed')
    } finally {
      if (!cancelRef.current) setLoading(false)
    }
  }

  useEffect(() => {
    cancelRef.current = false
    refresh()
    const t = setInterval(refresh, REFRESH_MS)
    const onFocus = () => refresh()
    window.addEventListener('focus', onFocus)
    return () => {
      cancelRef.current = true
      clearInterval(t)
      window.removeEventListener('focus', onFocus)
    }
  }, [])

  // keep "updated Xs ago" ticking once per second
  useEffect(() => {
    const i = setInterval(() => setNow(Date.now()), 1000)
    return () => clearInterval(i)
  }, [])

  if (loading && !kpis) {
    return (
      <div className="grid grid-cols-2 md:grid-cols-4 xl:grid-cols-8 gap-2 p-3 border-b border-white/5">
        {Array.from({ length: 8 }).map((_, i) => (
          <div key={i} className="h-[68px] rounded-xl bg-white/[0.03] border border-white/5 animate-pulse" />
        ))}
      </div>
    )
  }

  if (err && !kpis) {
    return (
      <div className="px-4 py-3 border-b border-rose-500/30 bg-rose-950/30 text-[12px] font-mono text-rose-200">
        Could not load executive KPIs: {err}
      </div>
    )
  }

  const sev = kpis?.severity || {}
  const delta = kpis?.severity_delta_24h || {}
  const score = kpis?.security_score ?? 0
  const scoreColor = score >= 80 ? '#22c55e' : score >= 60 ? '#fbbf24' : score >= 40 ? '#f97316' : '#ef4444'
  const agents = kpis?.agents || {}
  const jobs = kpis?.jobs || {}
  const assets = kpis?.assets || {}
  const trend = kpis?.trend || {}
  const mttr = kpis?.mttr_hours ?? 0
  const lastUpdated = kpis?.last_updated_unix

  const totalOpen =
    (sev.critical || 0) + (sev.high || 0) + (sev.medium || 0) + (sev.low || 0) + (sev.info || 0)

  return (
    <div className="border-b border-white/5 bg-gradient-to-b from-black/40 to-black/10 backdrop-blur-md">
      {/* Status bar */}
      <div className="flex items-center justify-between gap-3 px-3 sm:px-4 py-1.5 border-b border-white/[0.03] text-[10px] font-mono uppercase tracking-widest">
        <div className="flex items-center gap-2 text-white/55">
          <span
            className="inline-block w-1.5 h-1.5 rounded-full bg-emerald-400 animate-pulse"
            aria-hidden="true"
          />
          <span className="text-emerald-300/80">Live</span>
          <span className="text-white/30">·</span>
          <span>{jobs.running || 0} running</span>
          <span className="text-white/30">·</span>
          <span>{jobs.pending || 0} pending</span>
          <span className="text-white/30">·</span>
          <span>{agents.online || 0}/{agents.registered || 0} agents</span>
        </div>
        <div className="text-white/35 flex items-center gap-2">
          <span>updated {fmtAgo(lastUpdated)}</span>
          <button
            type="button"
            onClick={refresh}
            className="text-cyan-300/60 hover:text-cyan-200 normal-case"
            title="Refresh now"
          >
            ↻
          </button>
        </div>
      </div>

      {/* KPI grid */}
      <div className="grid grid-cols-2 md:grid-cols-4 xl:grid-cols-8 gap-2 px-3 sm:px-4 py-3">
        <Tile
          label="Score"
          value={
            <span className="flex items-baseline gap-1">
              <span style={{ color: scoreColor }}>{score}</span>
              <span className="text-[11px] text-white/35 font-mono">/100</span>
            </span>
          }
          color={scoreColor}
          to="/findings"
          ariaLabel={`Security score ${score} out of 100`}
          footer={`weighted (${kpis?.scoring?.method || 'severity'})`}
          intensity={2}
        />
        <Tile
          label="Critical"
          value={
            <span className="flex items-baseline gap-1.5">
              <span>{fmtCount(sev.critical)}</span>
              <DeltaArrow value={delta.critical} />
            </span>
          }
          color="#ef4444"
          to="/findings?severity=critical"
          footer={`${fmtCount(totalOpen)} open total`}
        />
        <Tile
          label="High"
          value={
            <span className="flex items-baseline gap-1.5">
              <span>{fmtCount(sev.high)}</span>
              <DeltaArrow value={delta.high} />
            </span>
          }
          color="#f97316"
          to="/findings?severity=high"
          footer={`${fmtCount(sev.medium)} medium`}
        />
        <Tile
          label="MTTR"
          value={
            <span className="flex items-baseline gap-1">
              <span>{mttr > 0 ? mttr.toFixed(1) : '—'}</span>
              <span className="text-[11px] text-white/35 font-mono">h</span>
            </span>
          }
          color="#a855f7"
          to="/findings?status=FIXED"
          footer="open → fixed (30d)"
        />
        <Tile
          label="Assets"
          value={
            <span className="flex items-baseline gap-1.5">
              <span>{fmtCount(assets.total_clients)}</span>
              <span className="text-[11px] text-white/40 font-mono">/{fmtCount(assets.with_findings)} at risk</span>
            </span>
          }
          color="#22d3ee"
          to="/clients"
          footer="clients monitored"
        />
        <Tile
          label="Agents"
          value={
            <span className="flex items-baseline gap-1.5">
              <span>{fmtCount(agents.online)}</span>
              <span className="text-[11px] text-white/40 font-mono">/{fmtCount(agents.registered)}</span>
            </span>
          }
          color={agents.online > 0 ? '#22c55e' : '#64748b'}
          to="/agents"
          footer={`${agents.stale || 0} stale`}
        />
        <Tile
          label="Jobs 24h"
          value={
            <span className="flex items-baseline gap-1.5">
              <span>{fmtCount(jobs.completed_24h)}</span>
              {jobs.failed_24h > 0 && (
                <span className="text-[11px] text-rose-400 font-mono" title="failed in last 24h">
                  ⚠ {jobs.failed_24h}
                </span>
              )}
            </span>
          }
          color="#3b82f6"
          to="/jobs"
          footer={`avg ${(kpis?.scan_velocity?.avg_scan_secs || 0).toFixed(1)}s`}
        />
        <Tile
          label="Trend 24h"
          value={
            <div className="flex items-center gap-2">
              <MiniSpark values={trend.discovered || []} color="#ef4444" height={28} />
            </div>
          }
          color="#ef4444"
          to="/findings"
          footer={`${(trend.discovered || []).reduce((a, b) => a + b, 0)} discovered`}
        />
      </div>
    </div>
  )
}
