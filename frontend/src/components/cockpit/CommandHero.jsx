import { useEffect, useMemo, useRef, useState } from 'react'
import { useTranslation } from 'react-i18next'
import { Link } from 'react-router'
import { motion } from 'framer-motion'
import {
  RefreshCw,
  TrendingDown,
  TrendingUp,
  Minus,
  Bot,
  Boxes,
  Timer,
  Gauge,
  Layers,
  ListChecks,
} from 'lucide-react'
import { apiFetch } from '../../utils/apiFetch'
import { useVisiblePolling } from '../../hooks/useVisiblePolling'
import { EngineRealitySummary } from '../EngineRealityBadge'
import Button from '../ui/Button'

const REFRESH_MS = 15_000

const NS = 'components.cockpitTabs.execKpiStrip'
const CH = 'components.commandHero'

const SEVERITY = [
  { key: 'critical', color: '#ef4444', labelKey: `${NS}.critical` },
  { key: 'high', color: '#f97316', labelKey: `${NS}.high` },
  { key: 'medium', color: '#f59e0b', labelKey: `${CH}.medium` },
  { key: 'low', color: '#22d3ee', labelKey: `${CH}.low` },
  { key: 'info', color: '#64748b', labelKey: `${CH}.info` },
]

function fmtCount(n) {
  if (n == null || Number.isNaN(n)) return '—'
  const v = Number(n)
  if (v >= 1_000_000) return `${(v / 1_000_000).toFixed(1)}M`
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

function scoreColor(score) {
  if (score == null) return '#94a3b8'
  if (score >= 80) return '#22c55e'
  if (score >= 60) return '#84cc16'
  if (score >= 40) return '#f59e0b'
  if (score >= 20) return '#f97316'
  return '#ef4444'
}

function postureKey(score) {
  if (score == null) return 'unknown'
  if (score >= 80) return 'robust'
  if (score >= 60) return 'guarded'
  if (score >= 40) return 'elevated'
  if (score >= 20) return 'high'
  return 'severe'
}

function Delta({ value, invert = true }) {
  const { t } = useTranslation()
  if (value == null || value === 0) {
    return (
      <span className="inline-flex items-center text-[var(--text-disabled)]" title={t(`${NS}.no_change_vs_24h`)}>
        <Minus className="w-3 h-3" strokeWidth={2} />
      </span>
    )
  }
  const up = value > 0
  // For findings, "up" (more findings) is bad → rose; for score, invert.
  const bad = invert ? up : !up
  const Icon = up ? TrendingUp : TrendingDown
  return (
    <span
      className={`inline-flex items-center gap-0.5 text-[10px] font-mono tabular-nums ${bad ? 'text-rose-400' : 'text-emerald-400'}`}
      title={t(`${NS}.delta_vs_24h`, { sign: up ? '+' : '', value })}
    >
      <Icon className="w-3 h-3" strokeWidth={2.5} />
      {Math.abs(value)}
    </span>
  )
}

/** Radial security-score gauge (full-ring, animated arc). */
function ScoreGauge({ score, method }) {
  const { t } = useTranslation()
  const col = scoreColor(score)
  const R = 54
  const C = 2 * Math.PI * R
  const pct = score == null ? 0 : Math.max(0, Math.min(100, score)) / 100
  const gid = 'ch-score-grad'
  return (
    <div className="flex flex-col items-center justify-center">
      <div className="relative" style={{ width: 148, height: 148 }}>
        <svg width="148" height="148" viewBox="0 0 148 148" aria-hidden="true">
          <defs>
            <linearGradient id={gid} x1="0" y1="0" x2="1" y2="1">
              <stop offset="0%" stopColor={col} stopOpacity="0.55" />
              <stop offset="100%" stopColor={col} stopOpacity="1" />
            </linearGradient>
          </defs>
          <circle cx="74" cy="74" r={R} fill="none" stroke="var(--border-default)" strokeWidth="10" opacity="0.6" />
          <motion.circle
            cx="74"
            cy="74"
            r={R}
            fill="none"
            stroke={`url(#${gid})`}
            strokeWidth="10"
            strokeLinecap="round"
            transform="rotate(-90 74 74)"
            strokeDasharray={C}
            initial={{ strokeDashoffset: C }}
            animate={{ strokeDashoffset: C * (1 - pct) }}
            transition={{ duration: 1.1, ease: 'easeOut' }}
            style={{ filter: `drop-shadow(0 0 6px ${col}66)` }}
          />
        </svg>
        <div className="absolute inset-0 flex flex-col items-center justify-center">
          <span className="text-4xl font-semibold tabular-nums leading-none tracking-tight" style={{ color: col }}>
            {score == null ? '—' : Math.round(score)}
          </span>
          <span className="text-[10px] font-mono text-[var(--text-muted)] mt-1">/100</span>
        </div>
      </div>
      <div className="mt-2 text-center flex flex-col items-center">
        <span
          className="px-2.5 py-0.5 rounded-full text-[9px] font-mono font-semibold uppercase tracking-[0.18em]"
          style={{ color: col, background: `${col}18`, boxShadow: `inset 0 0 0 1px ${col}44` }}
        >
          {t(`${CH}.posture.${postureKey(score)}`)}
        </span>
        <div className="text-[8px] font-mono uppercase tracking-[0.22em] text-[var(--text-tertiary)] mt-1.5">
          {t(`${CH}.security_posture`)}
        </div>
        <div className="text-[9px] font-mono text-[var(--text-muted)] mt-0.5 max-w-[160px] truncate">
          {method || t(`${NS}.severity_weighted`)}
        </div>
      </div>
    </div>
  )
}

/** Threat posture spectrum — proportional stacked bar + per-severity cells. */
function ThreatSpectrum({ sev, delta }) {
  const { t } = useTranslation()
  const counts = SEVERITY.map((s) => ({ ...s, n: sev[s.key] || 0, d: delta[s.key] }))
  const total = counts.reduce((a, b) => a + b.n, 0)
  return (
    <div className="flex flex-col justify-between h-full min-w-0">
      <div className="flex items-center justify-between mb-2">
        <span className="text-[10px] font-mono uppercase tracking-[0.22em] text-[var(--text-tertiary)]">
          {t(`${CH}.threat_posture`)}
        </span>
        <Link
          to="/findings"
          className="text-[10px] font-mono tabular-nums text-[var(--text-secondary)] hover:text-cyan-300 transition-colors"
        >
          {t(`${NS}.open_count`, { count: fmtCount(total) })}
        </Link>
      </div>
      {/* Proportional spectrum bar */}
      <div className="flex h-2 w-full rounded-full overflow-hidden bg-[var(--border-subtle)]">
        {total === 0 ? (
          <div className="w-full bg-emerald-500/30" />
        ) : (
          counts.map((c) =>
            c.n > 0 ? (
              <motion.div
                key={c.key}
                initial={{ width: 0 }}
                animate={{ width: `${(c.n / total) * 100}%` }}
                transition={{ duration: 0.8, ease: 'easeOut' }}
                style={{ background: c.color, boxShadow: `0 0 8px ${c.color}55` }}
                title={`${t(c.labelKey)}: ${c.n}`}
              />
            ) : null,
          )
        )}
      </div>
      {/* Per-severity cells */}
      <div className="grid grid-cols-5 gap-1.5 mt-3">
        {counts.map((c) => (
          <Link
            key={c.key}
            to={`/findings?severity=${c.key}`}
            className="group rounded-lg border border-[var(--border-subtle)] bg-[var(--bg-1)]/50 px-2 py-1.5 hover:border-[var(--border-strong)] transition-colors min-w-0"
          >
            <span className="block w-full h-0.5 rounded-full mb-1.5" style={{ background: c.color }} aria-hidden />
            <div className="flex items-baseline justify-between gap-1">
              <span className="text-base font-semibold tabular-nums text-[var(--text-primary)] leading-none">
                {fmtCount(c.n)}
              </span>
              <Delta value={c.d} />
            </div>
            <div className="text-[8px] font-mono uppercase tracking-[0.14em] text-[var(--text-muted)] mt-1 truncate">
              {t(c.labelKey)}
            </div>
          </Link>
        ))}
      </div>
    </div>
  )
}

/** Gradient area sparkline (inline SVG — theme-safe, no deps). */
function TrendSpark({ values, color = '#ef4444' }) {
  const W = 240
  const H = 56
  const pad = 2
  const path = useMemo(() => {
    if (!values || values.length === 0) return { line: '', area: '' }
    const max = Math.max(1, ...values)
    const n = values.length
    const step = (W - pad * 2) / Math.max(1, n - 1)
    const pts = values.map((v, i) => {
      const x = pad + i * step
      const y = H - pad - (v / max) * (H - pad * 2)
      return [x, y]
    })
    const line = pts.map(([x, y], i) => `${i === 0 ? 'M' : 'L'}${x.toFixed(1)},${y.toFixed(1)}`).join(' ')
    const area = `${line} L${(pad + (n - 1) * step).toFixed(1)},${H - pad} L${pad},${H - pad} Z`
    return { line, area }
  }, [values])
  const gid = 'ch-trend-grad'
  return (
    <svg width="100%" height={H} viewBox={`0 0 ${W} ${H}`} preserveAspectRatio="none" aria-hidden="true">
      <defs>
        <linearGradient id={gid} x1="0" y1="0" x2="0" y2="1">
          <stop offset="0%" stopColor={color} stopOpacity="0.35" />
          <stop offset="100%" stopColor={color} stopOpacity="0" />
        </linearGradient>
      </defs>
      {path.area && <path d={path.area} fill={`url(#${gid})`} />}
      {path.line && (
        <path d={path.line} fill="none" stroke={color} strokeWidth="1.75" strokeLinecap="round" strokeLinejoin="round" />
      )}
    </svg>
  )
}

function KpiChip({ icon: Icon, label, value, sub, color = '#22d3ee', to }) {
  const body = (
    <div className="group flex items-center gap-3 rounded-xl border border-[var(--border-subtle)] bg-[var(--bg-1)]/50 px-3 py-2.5 hover:border-[var(--border-strong)] hover:bg-[var(--row-hover-bg)] transition-colors min-w-0 h-full">
      <span
        className="shrink-0 grid place-items-center w-9 h-9 rounded-lg"
        style={{ background: `${color}14`, color, boxShadow: `inset 0 0 0 1px ${color}33` }}
      >
        <Icon className="w-4 h-4" strokeWidth={2} />
      </span>
      <div className="min-w-0">
        <div className="text-[9px] font-mono uppercase tracking-[0.16em] text-[var(--text-muted)] truncate">{label}</div>
        <div className="flex items-baseline gap-1 mt-0.5 min-w-0">
          <span className="text-lg font-semibold tabular-nums text-[var(--text-primary)] leading-none">{value}</span>
          {sub != null && <span className="text-[10px] font-mono text-[var(--text-muted)] truncate">{sub}</span>}
        </div>
      </div>
    </div>
  )
  return to ? (
    <Link to={to} className="block min-w-0 focus:outline-none focus-visible:ring-1 focus-visible:ring-cyan-400/40 rounded-xl">
      {body}
    </Link>
  ) : (
    body
  )
}

export default function CommandHero() {
  const { t } = useTranslation()
  const [kpis, setKpis] = useState(null)
  const [loading, setLoading] = useState(true)
  const [err, setErr] = useState(null)
  const cancelRef = useRef(false)
  const abortRef = useRef(null)
  const inflightRef = useRef(false)

  const refresh = async ({ silent = false } = {}) => {
    if (silent && inflightRef.current) return
    if (!silent) abortRef.current?.abort()
    const ac = new AbortController()
    abortRef.current = ac
    inflightRef.current = true
    try {
      const d = await apiFetch('/api/dashboard/exec-kpis', { signal: ac.signal })
      if (ac.signal.aborted) return
      if (d?.ok === false || d?.unavailable) {
        throw new Error(d.detail || t(`${NS}.fetch_failed`))
      }
      if (!cancelRef.current) {
        setKpis(d)
        setErr(null)
      }
    } catch (e) {
      if (e?.name === 'AbortError' || ac.signal.aborted) return
      if (!cancelRef.current) {
        setErr(e?.message || t(`${NS}.fetch_failed`))
        setKpis(null)
      }
    } finally {
      if (abortRef.current === ac) inflightRef.current = false
      if (!cancelRef.current && abortRef.current === ac && !ac.signal.aborted) setLoading(false)
    }
  }

  useEffect(() => {
    cancelRef.current = false
    refresh()
    const onFocus = () => refresh({ silent: true })
    window.addEventListener('focus', onFocus)
    return () => {
      cancelRef.current = true
      abortRef.current?.abort()
      window.removeEventListener('focus', onFocus)
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [])
  useVisiblePolling(() => refresh({ silent: true }), REFRESH_MS)

  if (loading && !kpis) {
    return (
      <div className="border-b border-[var(--border-subtle)] px-4 py-4" style={{ background: 'var(--kpi-strip-bg)' }}>
        <div className="grid grid-cols-1 lg:grid-cols-12 gap-4">
          <div className="lg:col-span-3 h-40 rounded-2xl bg-[var(--row-hover-bg)] animate-pulse" />
          <div className="lg:col-span-5 h-40 rounded-2xl bg-[var(--row-hover-bg)] animate-pulse" />
          <div className="lg:col-span-4 h-40 rounded-2xl bg-[var(--row-hover-bg)] animate-pulse" />
        </div>
      </div>
    )
  }

  if (err && !kpis) {
    return (
      <div
        className="px-4 py-3 border-b border-rose-500/25 bg-rose-950/25 text-[11px] font-mono text-rose-200"
        data-testid="exec-kpi-unavailable"
        role="alert"
      >
        {t(`${NS}.load_error`, { err })}
      </div>
    )
  }

  const sev = kpis?.severity || {}
  const delta = kpis?.severity_delta_24h || {}
  const score = kpis?.security_score
  const agents = kpis?.agents || {}
  const jobs = kpis?.jobs || {}
  const assets = kpis?.assets || {}
  const trend = kpis?.trend || {}
  const mttr = kpis?.mttr_hours ?? 0
  const lastUpdated = kpis?.last_updated_unix
  const discovered = trend.discovered || []
  const discovered24h = discovered.reduce((a, b) => a + b, 0)

  return (
    <motion.div
      initial={{ opacity: 0, y: -8 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ duration: 0.4, ease: 'easeOut' }}
      className="border-b border-[var(--border-subtle)] backdrop-blur-md"
      style={{ background: 'var(--kpi-strip-bg)' }}
    >
      {/* Top accent — subtle brand gradient hairline */}
      <div
        className="h-px w-full"
        aria-hidden
        style={{
          background:
            'linear-gradient(90deg, transparent 0%, color-mix(in srgb, var(--brand-primary) 55%, transparent) 30%, color-mix(in srgb, var(--brand-secondary) 45%, transparent) 70%, transparent 100%)',
        }}
      />
      {/* Live status bar */}
      <div className="flex items-center justify-between gap-3 px-4 py-1.5 border-b border-[var(--border-subtle)] text-[9px] font-mono uppercase tracking-[0.18em]">
        <div className="flex items-center gap-2 text-[var(--text-tertiary)] min-w-0 overflow-hidden">
          <span className="inline-flex items-center gap-1.5 shrink-0">
            <span className="w-1.5 h-1.5 rounded-full bg-emerald-400 animate-pulse" aria-hidden />
            <span className="text-emerald-400/90">{t(`${NS}.live`)}</span>
          </span>
          <span className="text-[var(--text-disabled)]">|</span>
          <span className="shrink-0">{t(`${NS}.run_count`, { count: fmtCount(jobs.running || 0) })}</span>
          <span className="text-[var(--text-disabled)]">|</span>
          <span className="shrink-0">{t(`${NS}.queue_count`, { count: fmtCount(jobs.pending || 0) })}</span>
          <span className="text-[var(--text-disabled)] hidden sm:inline">|</span>
          <span className="hidden sm:inline shrink-0">
            {t(`${NS}.agents_count`, { online: fmtCount(agents.online || 0), registered: fmtCount(agents.registered || 0) })}
          </span>
          <span className="text-[var(--text-disabled)] hidden lg:inline">|</span>
          <Link to="/engine-reliability" className="hidden lg:inline-flex items-center hover:text-cyan-300/90 transition-colors shrink-0">
            <EngineRealitySummary compact className="text-[8px]" />
          </Link>
        </div>
        <div className="text-[var(--text-muted)] flex items-center gap-1.5 tabular-nums shrink-0">
          <span>{fmtAgo(lastUpdated)}</span>
          <Button
            variant="unstyled"
            type="button"
            onClick={() => refresh()}
            className="text-cyan-400/60 hover:text-cyan-300 transition-colors p-0.5"
            title={t(`${NS}.refresh_now`)}
            aria-label={t(`${NS}.refresh_kpis`)}
          >
            <RefreshCw className="w-3 h-3" strokeWidth={2} />
          </Button>
        </div>
      </div>

      {/* Hero grid */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-3 p-3 sm:p-4">
        <div className="lg:col-span-3 rounded-2xl border border-[var(--border-subtle)] bg-[var(--bg-1)]/50 shadow-[0_8px_30px_-14px_rgba(0,0,0,0.45)] p-3 flex items-center justify-center">
          <Link to="/findings" className="focus:outline-none focus-visible:ring-1 focus-visible:ring-cyan-400/40 rounded-xl">
            <ScoreGauge score={score} method={kpis?.scoring?.method} />
          </Link>
        </div>
        <div className="lg:col-span-5 rounded-2xl border border-[var(--border-subtle)] bg-[var(--bg-1)]/50 shadow-[0_8px_30px_-14px_rgba(0,0,0,0.45)] p-3.5">
          <ThreatSpectrum sev={sev} delta={delta} />
        </div>
        <div className="lg:col-span-4 rounded-2xl border border-[var(--border-subtle)] bg-[var(--bg-1)]/50 shadow-[0_8px_30px_-14px_rgba(0,0,0,0.45)] p-3.5 flex flex-col justify-between min-w-0">
          <div className="flex items-center justify-between">
            <span className="text-[10px] font-mono uppercase tracking-[0.22em] text-[var(--text-tertiary)]">
              {t(`${CH}.discovery_trend`)}
            </span>
            <span className="text-[10px] font-mono tabular-nums text-[var(--text-secondary)]">
              {t(`${NS}.trend_24h`, { count: fmtCount(discovered24h) })}
            </span>
          </div>
          <div className="mt-2 -mx-1">
            <TrendSpark values={discovered} color="#ef4444" />
          </div>
          <div className="grid grid-cols-2 gap-1.5 mt-2">
            <KpiChip icon={Timer} label={t(`${NS}.mttr`)} value={mttr > 0 ? mttr.toFixed(1) : '—'} sub={t(`${NS}.hours_abbr`)} color="#a855f7" to="/findings?status=FIXED" />
            <KpiChip icon={Gauge} label={t(`${CH}.velocity`)} value={(kpis?.scan_velocity?.avg_scan_secs || 0).toFixed(1)} sub="s" color="#3b82f6" to="/jobs" />
          </div>
        </div>
      </div>

      {/* KPI chip row */}
      <div className="grid grid-cols-2 sm:grid-cols-4 gap-2 px-3 sm:px-4 pb-3 sm:pb-4">
        <KpiChip
          icon={Boxes}
          label={t(`${NS}.assets`)}
          value={fmtCount(assets.total_clients)}
          sub={t(`${NS}.risk_suffix`, { count: fmtCount(assets.with_findings) })}
          color="#22d3ee"
          to="/clients"
        />
        <KpiChip
          icon={Bot}
          label={t(`${NS}.agents`)}
          value={`${fmtCount(agents.online)}/${fmtCount(agents.registered)}`}
          sub={t(`${NS}.stale_count`, { count: agents.stale || 0 })}
          color={agents.online > 0 ? '#22c55e' : '#64748b'}
          to="/agents"
        />
        <KpiChip
          icon={ListChecks}
          label={t(`${NS}.jobs`)}
          value={fmtCount(jobs.completed_24h)}
          sub={jobs.failed_24h > 0 ? `${jobs.failed_24h}✕` : null}
          color="#3b82f6"
          to="/jobs"
        />
        <KpiChip
          icon={Layers}
          label={t(`${CH}.queue`)}
          value={fmtCount(jobs.running || 0)}
          sub={t(`${NS}.queue_count`, { count: fmtCount(jobs.pending || 0) })}
          color="#f59e0b"
          to="/jobs"
        />
      </div>
    </motion.div>
  )
}
