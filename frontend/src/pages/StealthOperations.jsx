import React, { useCallback, useEffect, useRef, useState } from 'react'
import { apiFetch } from '../lib/apiBase'

// Live-load tint by saturation ratio.
function loadColor(ratio) {
  if (ratio >= 0.85) return 'bg-rose-500'
  if (ratio >= 0.6) return 'bg-amber-500'
  if (ratio > 0) return 'bg-emerald-500'
  return 'bg-slate-600'
}

function Stat({ label, value, sub }) {
  return (
    <div className="rounded-lg border border-white/10 bg-slate-900/40 px-3 py-2.5">
      <div className="text-[10px] uppercase tracking-wider text-slate-500">{label}</div>
      <div className="text-xl font-semibold text-white tabular-nums font-mono">{value}</div>
      {sub && <div className="text-[10px] text-slate-500 mt-0.5">{sub}</div>}
    </div>
  )
}

// Horizontal saturation bar: in-flight vs capacity.
function LoadBar({ inFlight, capacity }) {
  const cap = Math.max(1, Number(capacity) || 1)
  const cur = Math.max(0, Number(inFlight) || 0)
  const ratio = Math.min(1, cur / cap)
  return (
    <div className="flex items-center gap-2">
      <div className="h-2 flex-1 rounded-full bg-white/10 overflow-hidden">
        <div className={`h-full ${loadColor(ratio)} transition-all`} style={{ width: `${ratio * 100}%` }} />
      </div>
      <span className="text-[11px] font-mono text-slate-300 tabular-nums w-12 text-right">
        {cur}/{cap}
      </span>
    </div>
  )
}

export default function StealthOperations() {
  const [data, setData] = useState(null)
  const [error, setError] = useState('')
  const [live, setLive] = useState(true)
  const [loading, setLoading] = useState(true)
  const timer = useRef(null)

  const load = useCallback(async () => {
    try {
      const r = await apiFetch('/api/stealth/status')
      if (!r.ok) {
        const j = await r.json().catch(() => ({}))
        throw new Error(j.detail || j.error || `HTTP ${r.status}`)
      }
      setData(await r.json())
      setError('')
    } catch (err) {
      setError((err && err.message) || 'request failed')
    } finally {
      setLoading(false)
    }
  }, [])

  useEffect(() => {
    load()
    if (live) {
      timer.current = setInterval(load, 2000)
      return () => clearInterval(timer.current)
    }
    return undefined
  }, [load, live])

  const cfg = data && data.config
  const l = data && data.live
  const id = data && data.identity
  const globalRatio = l && cfg ? (l.global_in_flight || 0) / Math.max(1, cfg.global_capacity) : 0

  return (
    <div className="mx-auto max-w-6xl px-4 py-6 text-slate-200">
      <header className="mb-5 flex items-start justify-between gap-4 flex-wrap">
        <div>
          <h1 className="text-2xl font-semibold tracking-tight text-white flex items-center gap-2">
            <span aria-hidden>🛡️</span> Stealth Operations
          </h1>
          <p className="text-sm text-slate-400 mt-1 max-w-2xl">
            Live view of the Smart Stealth Queue — the admission gateway that paces a full-arsenal
            launch into careful, human-cadence Red-Team traffic: per-target concurrency caps,
            global ceiling, jitter, adaptive pacing, and rotating browser identity.
          </p>
        </div>
        <div className="flex items-center gap-2">
          <button
            onClick={() => setLive((v) => !v)}
            className={`rounded-lg border px-3 py-1.5 text-xs font-medium transition-colors ${
              live
                ? 'border-emerald-500/40 bg-emerald-950/40 text-emerald-300'
                : 'border-white/15 bg-slate-900/60 text-slate-400'
            }`}
          >
            <span className={`inline-block w-1.5 h-1.5 rounded-full mr-1.5 ${live ? 'bg-emerald-400 animate-pulse' : 'bg-slate-500'}`} />
            {live ? 'Live · 2s' : 'Paused'}
          </button>
          <button
            onClick={load}
            className="rounded-lg border border-white/15 bg-slate-900/60 px-3 py-1.5 text-xs font-medium text-slate-300 hover:bg-slate-800/60"
          >
            Refresh
          </button>
        </div>
      </header>

      {error && (
        <div className="rounded-lg border border-rose-500/40 bg-rose-950/30 px-4 py-3 text-sm text-rose-300 mb-4">
          {error}
        </div>
      )}

      {loading && !data && (
        <div className="rounded-xl border border-dashed border-white/10 bg-slate-900/20 px-6 py-12 text-center text-sm text-slate-500">
          Loading stealth queue telemetry…
        </div>
      )}

      {data && (
        <>
          {data.disabled && (
            <div className="rounded-lg border border-amber-500/40 bg-amber-950/30 px-4 py-3 text-sm text-amber-300 mb-4">
              ⚠ Stealth shaping is <span className="font-mono">DISABLED</span> (WEISSMAN_STEALTH_DISABLED).
              Requests are not being paced or capped — intended only for offline/CI runs.
            </div>
          )}

          {/* ── Live metrics ── */}
          <div className="grid grid-cols-2 sm:grid-cols-4 gap-3 mb-5">
            <Stat
              label="Global in-flight"
              value={`${l.global_in_flight}`}
              sub={`of ${cfg.global_capacity} · ${l.global_free} free`}
            />
            <Stat label="Queued / waiting" value={`${l.waiting}`} sub="parked for a slot" />
            <Stat label="Active hosts" value={`${l.active_hosts.length}`} sub={`${l.tracked_hosts} tracked`} />
            <Stat label="Admitted total" value={l.admitted_total.toLocaleString()} sub="since start" />
          </div>

          <div className="mb-5">
            <div className="text-[11px] uppercase tracking-wider text-slate-500 mb-1">
              Global egress saturation
            </div>
            <LoadBar inFlight={l.global_in_flight} capacity={cfg.global_capacity} />
          </div>

          <div className="grid gap-5 md:grid-cols-2">
            {/* ── Config ── */}
            <section className="rounded-xl border border-white/10 bg-slate-900/40 p-4">
              <h2 className="text-sm font-semibold uppercase tracking-wider text-slate-400 mb-3">
                Effective configuration
              </h2>
              <p className="text-xs text-slate-500 mb-3">
                Caps are set at deploy time via environment variables — a safety-critical rate
                limiter is never weakened from the console.
              </p>
              <dl className="space-y-2">
                {[
                  ['Per-target concurrency', cfg.per_target, cfg.env_keys.per_target],
                  ['Global ceiling', cfg.global_capacity, cfg.env_keys.global],
                  ['Jitter min (ms)', cfg.jitter_min_ms, cfg.env_keys.jitter_min_ms],
                  ['Jitter max (ms)', cfg.jitter_max_ms, cfg.env_keys.jitter_max_ms],
                  ['Min interval (ms)', cfg.min_interval_ms, cfg.env_keys.min_interval_ms],
                ].map(([k, v, env]) => (
                  <div key={k} className="flex items-baseline justify-between gap-3 border-b border-white/5 pb-2 last:border-0">
                    <div className="min-w-0">
                      <div className="text-sm text-slate-200">{k}</div>
                      <div className="text-[10px] font-mono text-slate-600 truncate">{env}</div>
                    </div>
                    <span className="text-lg font-mono font-semibold text-cyan-300 tabular-nums shrink-0">
                      {v}
                    </span>
                  </div>
                ))}
              </dl>
            </section>

            {/* ── Rotating identity ── */}
            <section className="rounded-xl border border-white/10 bg-slate-900/40 p-4">
              <h2 className="text-sm font-semibold uppercase tracking-wider text-slate-400 mb-3">
                Rotating identity
              </h2>
              <p className="text-xs text-slate-500 mb-3">
                Each admission is stamped with a realistic browser identity so traffic blends in as
                ordinary client sessions.
              </p>
              <div className="grid grid-cols-3 gap-3 mb-4">
                <Stat label="User-Agents" value={id.user_agent_pool} />
                <Stat label="Accept-Lang" value={id.accept_language_pool} />
                <Stat label="Platforms" value={id.platform_pool} />
              </div>
              <div className="rounded-lg border border-white/5 bg-white/[0.02] px-3 py-2">
                <div className="text-[10px] uppercase tracking-wider text-slate-500">
                  Identities dispensed
                </div>
                <div className="text-lg font-mono font-semibold text-white tabular-nums">
                  {id.identities_dispensed.toLocaleString()}
                </div>
              </div>
            </section>
          </div>

          {/* ── Active hosts ── */}
          <section className="rounded-xl border border-white/10 bg-slate-900/40 p-4 mt-5">
            <div className="flex items-center justify-between mb-3">
              <h2 className="text-sm font-semibold uppercase tracking-wider text-slate-400">
                Active targets · live load
              </h2>
              <span className="text-xs font-mono text-slate-500">
                showing {l.active_hosts.length}
              </span>
            </div>
            {l.active_hosts.length === 0 ? (
              <div className="text-sm text-slate-500 py-6 text-center">
                No requests in flight. Launch a scan to see the queue shape traffic per target.
              </div>
            ) : (
              <ul className="space-y-2">
                {l.active_hosts.map((h) => (
                  <li key={h.host} className="flex items-center gap-3">
                    <span className="text-sm font-mono text-slate-200 truncate w-56 shrink-0" title={h.host}>
                      {h.host}
                    </span>
                    <span className="flex-1">
                      <LoadBar inFlight={h.in_flight} capacity={h.capacity} />
                    </span>
                  </li>
                ))}
              </ul>
            )}
          </section>
        </>
      )}
    </div>
  )
}
