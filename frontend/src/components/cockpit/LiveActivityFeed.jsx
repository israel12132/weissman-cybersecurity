import React, { useMemo, useState } from 'react'
import { useTelemetry } from '../../context/TelemetryContext'

/**
 * Live Activity Feed — scrolling event panel inspired by Datadog Security Signals and
 * CrowdStrike Falcon "Activity Stream". Subscribes to the existing SSE telemetry
 * channel and renders the last N events with:
 *   - severity-tinted dot
 *   - icon per event kind (scan / finding / agent / orchestrator / error)
 *   - relative timestamp ("12s ago") that updates live
 *   - "scope" badges (engine id, target host, client id) when present
 *   - filter chips (All / Errors / Findings / Scans / Agents)
 *
 * Pure presentation — all state comes from `TelemetryContext`. Component is safe to
 * mount anywhere; multiple instances share the same feed.
 */

const KIND_META = {
  finding:      { icon: '◉', color: '#f97316', label: 'Finding' },
  scan_start:   { icon: '▶', color: '#22d3ee', label: 'Scan' },
  scan_done:    { icon: '✓', color: '#22c55e', label: 'Done' },
  agent:        { icon: '⬢', color: '#a855f7', label: 'Agent' },
  orchestrator: { icon: '◆', color: '#3b82f6', label: 'Orch' },
  heartbeat:    { icon: '·', color: '#475569', label: 'Beat' },
  error:        { icon: '⚠', color: '#ef4444', label: 'Error' },
  info:         { icon: 'ℹ', color: '#94a3b8', label: 'Info' },
  raw:          { icon: '?', color: '#64748b', label: 'Raw' },
}

const FILTERS = [
  { id: 'all',      label: 'All' },
  { id: 'finding',  label: 'Findings' },
  { id: 'scan',     label: 'Scans' },
  { id: 'agent',    label: 'Agents' },
  { id: 'error',    label: 'Errors' },
]

function fmtAgo(ts, nowMs) {
  const s = Math.max(0, Math.floor((nowMs - ts) / 1000))
  if (s < 60)   return `${s}s`
  if (s < 3600) return `${Math.floor(s / 60)}m`
  return `${Math.floor(s / 3600)}h`
}

function matchFilter(filter, kind) {
  if (filter === 'all') return true
  if (filter === 'scan') return kind === 'scan_start' || kind === 'scan_done'
  return kind === filter
}

export default function LiveActivityFeed({ maxHeight = 360, className = '' }) {
  const { activity, connected, clearActivity } = useTelemetry()
  const [filter, setFilter] = useState('all')
  const [paused, setPaused] = useState(false)
  const [now, setNow] = useState(Date.now())
  const pausedSnapshot = React.useRef([])

  React.useEffect(() => {
    const t = setInterval(() => setNow(Date.now()), 1000)
    return () => clearInterval(t)
  }, [])

  React.useEffect(() => {
    if (paused) {
      pausedSnapshot.current = activity
    }
  }, [paused, activity])

  const visible = useMemo(() => {
    const source = paused ? pausedSnapshot.current : activity
    return source.filter((e) => matchFilter(filter, e.kind)).slice(0, 80)
  }, [activity, filter, paused])

  return (
    <section
      className={`flex flex-col rounded-2xl border border-white/10 bg-black/35 backdrop-blur-md ${className}`}
      aria-label="Live activity feed"
    >
      {/* Header */}
      <header className="flex items-center justify-between gap-2 px-3 py-2 border-b border-white/[0.06]">
        <div className="flex items-center gap-2 min-w-0">
          <span
            className={`inline-block w-1.5 h-1.5 rounded-full ${
              connected ? 'bg-emerald-400 animate-pulse' : 'bg-rose-500'
            }`}
            aria-hidden="true"
            title={connected ? 'Telemetry connected' : 'Reconnecting…'}
          />
          <h3 className="text-[11px] font-mono uppercase tracking-[0.18em] text-white/75 truncate">
            Activity stream
          </h3>
          <span className="text-[10px] font-mono text-white/35 ml-1">
            {activity.length}
          </span>
        </div>
        <div className="flex items-center gap-1 shrink-0">
          <button
            type="button"
            onClick={() => setPaused((p) => !p)}
            className={`text-[10px] font-mono px-2 py-0.5 rounded border ${
              paused
                ? 'border-amber-500/40 text-amber-200 bg-amber-500/10'
                : 'border-white/10 text-white/55 hover:text-white/85'
            }`}
            title={paused ? 'Resume' : 'Pause stream'}
            aria-pressed={paused}
          >
            {paused ? '▶ Resume' : '⏸ Pause'}
          </button>
          <button
            type="button"
            onClick={clearActivity}
            className="text-[10px] font-mono px-2 py-0.5 rounded border border-white/10 text-white/45 hover:text-white/80"
            title="Clear log"
          >
            Clear
          </button>
        </div>
      </header>

      {/* Filter chips */}
      <div className="flex items-center gap-1 px-3 py-1.5 border-b border-white/[0.04] overflow-x-auto">
        {FILTERS.map((f) => {
          const active = filter === f.id
          return (
            <button
              key={f.id}
              type="button"
              onClick={() => setFilter(f.id)}
              aria-pressed={active}
              className={`text-[10px] font-mono px-2 py-0.5 rounded transition-colors ${
                active
                  ? 'bg-cyan-500/20 text-cyan-200 border border-cyan-500/40'
                  : 'text-white/50 hover:text-white/85 border border-transparent'
              }`}
            >
              {f.label}
            </button>
          )
        })}
      </div>

      {/* Event list */}
      <div
        className="overflow-y-auto divide-y divide-white/[0.04] custom-scroll"
        style={{ maxHeight }}
        aria-live="polite"
      >
        {visible.length === 0 ? (
          <div className="px-3 py-12 text-center text-[11px] font-mono text-white/35">
            {activity.length === 0
              ? 'Waiting for telemetry events…'
              : 'Nothing matches this filter.'}
          </div>
        ) : (
          visible.map((e) => {
            const meta = KIND_META[e.kind] || KIND_META.info
            return (
              <div
                key={e.id}
                className="flex items-start gap-2 px-3 py-1.5 hover:bg-white/[0.025] group"
              >
                <span
                  className="mt-1 inline-flex items-center justify-center text-[11px] shrink-0 w-4 h-4 rounded-full"
                  style={{
                    color: meta.color,
                    background: `${meta.color}18`,
                    border: `1px solid ${meta.color}40`,
                  }}
                  aria-hidden="true"
                >
                  {meta.icon}
                </span>
                <div className="min-w-0 flex-1">
                  <div className="flex items-center gap-1.5 text-[10px] font-mono text-white/40 uppercase tracking-widest">
                    <span style={{ color: meta.color }}>{meta.label}</span>
                    {e.engine && (
                      <>
                        <span className="text-white/15">·</span>
                        <span className="truncate text-white/55">{e.engine}</span>
                      </>
                    )}
                    {e.target && (
                      <>
                        <span className="text-white/15">·</span>
                        <span className="truncate text-cyan-300/70">{e.target}</span>
                      </>
                    )}
                    <span className="ms-auto text-white/30 normal-case">
                      {fmtAgo(e.t, now)} ago
                    </span>
                  </div>
                  <p className="text-[12px] text-white/80 leading-snug break-words mt-0.5">
                    {e.message}
                  </p>
                </div>
              </div>
            )
          })
        )}
      </div>
    </section>
  )
}
