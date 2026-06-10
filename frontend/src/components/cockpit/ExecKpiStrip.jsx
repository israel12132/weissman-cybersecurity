import React, { useEffect, useMemo, useRef, useState } from 'react'
import { Link } from 'react-router-dom'
import { RefreshCw, TrendingDown, TrendingUp, Minus } from 'lucide-react'
import { apiFetch } from '../../lib/apiBase'

const REFRESH_MS = 15_000

function fmtCount(n) {
  if (n == null || Number.isNaN(n)) return '—'
  const v = Number(n)
  if (v >= 1_000_000) return `${(v / 1_000_000).toFixed(1)}M`
  if (v >= 100_000) return `${Math.round(v / 1000)}k`
  if (v >= 10_000) return `${(v / 1000).toFixed(0)}k`
  if (v >= 1_000) return `${(v / 1000).toFixed(1)}k`
  return v.toLocaleString()
}

function fmtAgo(unix) {
  if (!unix) return '—'
  const s = Math.max(0, Math.floor(Date.now() / 1000 - unix))
  if (s < 60) return `${s}s`
  if (s < 3600) return `${Math.floor(s / 60)}m`
  return `${Math.floor(s / 3600)}h`
}

function DeltaArrow({ value }) {
  if (value == null || value === 0) {
    return (
      <span className="inline-flex items-center text-white/25" title="No change vs. 24h">
        <Minus className="w-2.5 h-2.5" strokeWidth={2} />
      </span>
    )
  }
  const up = value > 0
  const Icon = up ? TrendingUp : TrendingDown
  return (
    <span
      className={`inline-flex items-center gap-0.5 text-[9px] font-mono tabular-nums ${
        up ? 'text-rose-400' : 'text-emerald-400'
      }`}
      title={`${up ? '+' : ''}${value} vs. 24h ago`}
    >
      <Icon className="w-2.5 h-2.5" strokeWidth={2.5} />
      {Math.abs(value)}
    </span>
  )
}

function Tile({ label, value, footer, color = '#22d3ee', to, intensity = 1, ariaLabel, showDivider }) {
  const inner = (
    <div
      className={`group relative flex flex-col justify-between px-3 py-2 min-w-0 h-full transition-colors hover:bg-white/[0.02] ${
        showDivider ? 'border-e border-white/[0.04] last:border-e-0' : ''
      }`}
      role={to ? undefined : 'group'}
      aria-label={ariaLabel || label}
    >
      {intensity > 1 && (
        <div
          className="absolute inset-0 rounded-sm opacity-0 group-hover:opacity-100 transition-opacity pointer-events-none"
          style={{ boxShadow: `inset 0 0 0 1px ${color}18` }}
        />
      )}
      <div className="flex items-center justify-between gap-1 min-w-0">
        <span
          className="text-[8px] font-mono uppercase tracking-[0.2em] truncate"
          style={{ color: `${color}99` }}
        >
          {label}
        </span>
        <span
          className="w-1 h-1 rounded-full opacity-80 shrink-0"
          style={{ background: color, boxShadow: `0 0 4px ${color}60` }}
          aria-hidden="true"
        />
      </div>
      <div className="flex items-baseline gap-1 mt-1">
        <span className="text-[1.35rem] font-semibold tabular-nums leading-none tracking-tight text-slate-100">
          {value}
        </span>
      </div>
      {footer && (
        <div className="text-[9px] font-mono text-white/38 mt-1 truncate tracking-wide">{footer}</div>
      )}
    </div>
  )
  if (to) {
    return (
      <Link to={to} className="block min-w-0 h-full focus:outline-none focus-visible:ring-1 focus-visible:ring-cyan-400/40 rounded-sm">
        {inner}
      </Link>
    )
  }
  return inner
}

function MiniSpark({ values, color = '#22d3ee', height = 24 }) {
  const path = useMemo(() => {
    if (!values || values.length === 0) return ''
    const max = Math.max(1, ...values)
    const w = 72
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
    <svg width="72" height={height} viewBox={`0 0 72 ${height}`} aria-hidden="true" className="opacity-90">
      <path d={path} fill="none" stroke={color} strokeWidth="1.2" strokeLinecap="round" strokeLinejoin="round" />
    </svg>
  )
}

export default function ExecKpiStrip() {
  const [kpis, setKpis] = useState(null)
  const [loading, setLoading] = useState(true)
  const [err, setErr] = useState(null)
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

  if (loading && !kpis) {
    return (
      <div className="border-b border-white/[0.04] bg-[#050810]/80">
        <div className="h-7 border-b border-white/[0.03] bg-white/[0.01] animate-pulse" />
        <div className="grid grid-cols-2 md:grid-cols-4 xl:grid-cols-8 gap-px p-px bg-white/[0.03]">
          {Array.from({ length: 8 }).map((_, i) => (
            <div key={i} className="h-[58px] bg-[#0a0f18]/60 animate-pulse" />
          ))}
        </div>
      </div>
    )
  }

  if (err && !kpis) {
    return (
      <div className="px-4 py-2.5 border-b border-rose-500/25 bg-rose-950/25 text-[11px] font-mono text-rose-200">
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
    <div
      className="border-b border-white/[0.04] backdrop-blur-md"
      style={{
        background: 'linear-gradient(180deg, rgba(8,12,20,0.92) 0%, rgba(5,8,14,0.75) 100%)',
      }}
    >
      {/* Status ticker */}
      <div className="flex items-center justify-between gap-3 px-3 sm:px-4 py-1 border-b border-white/[0.03] text-[9px] font-mono uppercase tracking-[0.18em]">
        <div className="flex items-center gap-2 text-white/45">
          <span className="inline-flex items-center gap-1.5">
            <span className="w-1 h-1 rounded-full bg-emerald-400 animate-pulse" aria-hidden />
            <span className="text-emerald-400/80">Live</span>
          </span>
          <span className="text-white/20">|</span>
          <span>{fmtCount(jobs.running || 0)} run</span>
          <span className="text-white/20">|</span>
          <span>{fmtCount(jobs.pending || 0)} q</span>
          <span className="text-white/20 hidden sm:inline">|</span>
          <span className="hidden sm:inline">{fmtCount(agents.online || 0)}/{fmtCount(agents.registered || 0)} agt</span>
        </div>
        <div className="text-white/30 flex items-center gap-1.5 tabular-nums">
          <span>{fmtAgo(lastUpdated)}</span>
          <button
            type="button"
            onClick={refresh}
            className="text-cyan-400/50 hover:text-cyan-300/80 transition-colors p-0.5"
            title="Refresh now"
            aria-label="Refresh KPIs"
          >
            <RefreshCw className="w-3 h-3" strokeWidth={2} />
          </button>
        </div>
      </div>

      {/* KPI strip — Bloomberg-style dense row */}
      <div className="grid grid-cols-2 md:grid-cols-4 xl:grid-cols-8 gap-px bg-white/[0.03] mx-0">
        <Tile
          label="Score"
          value={
            <span className="flex items-baseline gap-0.5">
              <span style={{ color: scoreColor }}>{fmtCount(score)}</span>
              <span className="text-[10px] text-white/30 font-mono font-normal">/100</span>
            </span>
          }
          color={scoreColor}
          to="/findings"
          ariaLabel={`Security score ${score} out of 100`}
          footer={kpis?.scoring?.method || 'severity-weighted'}
          intensity={2}
          showDivider
        />
        <Tile
          label="Critical"
          value={
            <span className="flex items-baseline gap-1">
              <span>{fmtCount(sev.critical)}</span>
              <DeltaArrow value={delta.critical} />
            </span>
          }
          color="#ef4444"
          to="/findings?severity=critical"
          footer={`${fmtCount(totalOpen)} open`}
          showDivider
        />
        <Tile
          label="High"
          value={
            <span className="flex items-baseline gap-1">
              <span>{fmtCount(sev.high)}</span>
              <DeltaArrow value={delta.high} />
            </span>
          }
          color="#f97316"
          to="/findings?severity=high"
          footer={`${fmtCount(sev.medium)} med`}
          showDivider
        />
        <Tile
          label="MTTR"
          value={
            <span className="flex items-baseline gap-0.5">
              <span>{mttr > 0 ? mttr.toFixed(1) : '—'}</span>
              <span className="text-[10px] text-white/30 font-mono font-normal">h</span>
            </span>
          }
          color="#a855f7"
          to="/findings?status=FIXED"
          footer="30d window"
          showDivider
        />
        <Tile
          label="Assets"
          value={
            <span className="flex items-baseline gap-1">
              <span>{fmtCount(assets.total_clients)}</span>
              <span className="text-[10px] text-white/35 font-mono font-normal">/{fmtCount(assets.with_findings)} risk</span>
            </span>
          }
          color="#22d3ee"
          to="/clients"
          footer="monitored"
          showDivider
        />
        <Tile
          label="Agents"
          value={
            <span className="flex items-baseline gap-1">
              <span>{fmtCount(agents.online)}</span>
              <span className="text-[10px] text-white/35 font-mono font-normal">/{fmtCount(agents.registered)}</span>
            </span>
          }
          color={agents.online > 0 ? '#22c55e' : '#64748b'}
          to="/agents"
          footer={`${agents.stale || 0} stale`}
          showDivider
        />
        <Tile
          label="Jobs"
          value={
            <span className="flex items-baseline gap-1">
              <span>{fmtCount(jobs.completed_24h)}</span>
              {jobs.failed_24h > 0 && (
                <span className="text-[9px] text-rose-400 font-mono" title="failed in last 24h">
                  {jobs.failed_24h}✕
                </span>
              )}
            </span>
          }
          color="#3b82f6"
          to="/jobs"
          footer={`${(kpis?.scan_velocity?.avg_scan_secs || 0).toFixed(1)}s avg`}
          showDivider
        />
        <Tile
          label="Trend"
          value={<MiniSpark values={trend.discovered || []} color="#ef4444" height={24} />}
          color="#ef4444"
          to="/findings"
          footer={`${fmtCount((trend.discovered || []).reduce((a, b) => a + b, 0))} 24h`}
          showDivider
        />
      </div>
    </div>
  )
}
