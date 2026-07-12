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
  const [pacing, setPacing] = useState(null) // editable draft, seeded once from status
  const [saving, setSaving] = useState(false)
  const [saveMsg, setSaveMsg] = useState('')
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

  // Seed the editable pacing draft once (live polling must not clobber edits).
  useEffect(() => {
    if (data && data.config && pacing === null) {
      setPacing({
        jitter_min_ms: data.config.jitter_min_ms,
        jitter_max_ms: data.config.jitter_max_ms,
        min_interval_ms: data.config.min_interval_ms,
      })
    }
  }, [data, pacing])

  const setP = (k) => (ev) => {
    const n = Math.max(0, Math.min(60000, Math.floor(Number(ev.target.value) || 0)))
    setPacing((p) => ({ ...p, [k]: n }))
    setSaveMsg('')
  }

  const savePacing = async () => {
    if (!pacing) return
    setSaving(true)
    setSaveMsg('')
    try {
      const r = await apiFetch('/api/stealth/config', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(pacing),
      })
      if (!r.ok) {
        const j = await r.json().catch(() => ({}))
        throw new Error(j.detail || j.error || `HTTP ${r.status}`)
      }
      const fresh = await r.json()
      setData(fresh)
      setPacing({
        jitter_min_ms: fresh.config.jitter_min_ms,
        jitter_max_ms: fresh.config.jitter_max_ms,
        min_interval_ms: fresh.config.min_interval_ms,
      })
      setSaveMsg('Applied ✓')
    } catch (err) {
      setSaveMsg((err && err.message) || 'save failed')
    } finally {
      setSaving(false)
    }
  }

  const pacingDirty =
    pacing &&
    data &&
    data.config &&
    (pacing.jitter_min_ms !== data.config.jitter_min_ms ||
      pacing.jitter_max_ms !== data.config.jitter_max_ms ||
      pacing.min_interval_ms !== data.config.min_interval_ms)

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
              {/* Protection floor — env-only, read-only. */}
              <div className="text-[11px] uppercase tracking-wider text-slate-500 mb-1">
                Concurrency caps · protection floor
              </div>
              <p className="text-xs text-slate-500 mb-2">
                Set at deploy time via env — the DoS/WAF protection floor is never lowered from the
                console. Restart to change.
              </p>
              <dl className="space-y-2 mb-4">
                {[
                  ['Per-target concurrency', cfg.per_target, cfg.env_keys.per_target],
                  ['Global ceiling', cfg.global_capacity, cfg.env_keys.global],
                ].map(([k, v, env]) => (
                  <div key={k} className="flex items-baseline justify-between gap-3 border-b border-white/5 pb-2 last:border-0">
                    <div className="min-w-0">
                      <div className="text-sm text-slate-200">{k}</div>
                      <div className="text-[10px] font-mono text-slate-600 truncate">{env}</div>
                    </div>
                    <span className="text-lg font-mono font-semibold text-slate-300 tabular-nums shrink-0">
                      {v}
                    </span>
                  </div>
                ))}
              </dl>

              {/* Pacing — live-tunable within the enforced envelope (operator+). */}
              <div className="text-[11px] uppercase tracking-wider text-slate-500 mb-1">
                Pacing · live-tunable (operator+)
              </div>
              <p className="text-xs text-slate-500 mb-3">
                Adjust cadence within the caps. Applied instantly, clamped 0–60000 ms, audit-logged.
              </p>
              <div className="space-y-2">
                {pacing &&
                  [
                    ['Jitter min (ms)', 'jitter_min_ms'],
                    ['Jitter max (ms)', 'jitter_max_ms'],
                    ['Min interval (ms)', 'min_interval_ms'],
                  ].map(([k, key]) => (
                    <label key={key} className="flex items-center justify-between gap-3">
                      <span className="text-sm text-slate-200">{k}</span>
                      <input
                        type="number"
                        min="0"
                        max="60000"
                        value={pacing[key]}
                        onChange={setP(key)}
                        className="w-28 rounded-md border border-white/10 bg-slate-950/60 px-2 py-1 text-right text-sm font-mono text-cyan-300 tabular-nums focus:outline-none focus:ring-2 focus:ring-cyan-500/40"
                      />
                    </label>
                  ))}
              </div>
              <div className="mt-3 flex items-center gap-3">
                <button
                  onClick={savePacing}
                  disabled={!pacingDirty || saving}
                  className="rounded-lg bg-cyan-600 px-4 py-1.5 text-sm font-medium text-white hover:bg-cyan-500 disabled:opacity-40 disabled:cursor-not-allowed transition-colors"
                >
                  {saving ? 'Applying…' : 'Apply pacing'}
                </button>
                {saveMsg && (
                  <span
                    className={`text-xs font-mono ${saveMsg.includes('✓') ? 'text-emerald-400' : 'text-rose-400'}`}
                  >
                    {saveMsg}
                  </span>
                )}
              </div>
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
