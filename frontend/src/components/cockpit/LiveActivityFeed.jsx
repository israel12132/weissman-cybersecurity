import React, { useMemo, useState } from 'react'
import { useTranslation } from 'react-i18next'
import { useTelemetry } from '../../context/TelemetryContext'
import Button from '../ui/Button'

const NS = 'components.cockpitWidgets.liveActivityFeed'

const KIND_META = {
  finding:      { icon: '◉', color: '#f97316', labelKey: 'kinds.finding' },
  scan_start:   { icon: '▶', color: '#22d3ee', labelKey: 'kinds.scan_start' },
  scan_done:    { icon: '✓', color: '#22c55e', labelKey: 'kinds.scan_done' },
  agent:        { icon: '⬢', color: '#a855f7', labelKey: 'kinds.agent' },
  orchestrator: { icon: '◆', color: '#3b82f6', labelKey: 'kinds.orchestrator' },
  heartbeat:    { icon: '·', color: '#475569', labelKey: 'kinds.heartbeat' },
  error:        { icon: '⚠', color: '#ef4444', labelKey: 'kinds.error' },
  info:         { icon: 'ℹ', color: '#94a3b8', labelKey: 'kinds.info' },
  raw:          { icon: '?', color: '#64748b', labelKey: 'kinds.raw' },
}

const FILTERS = [
  { id: 'all',      labelKey: 'filters.all' },
  { id: 'finding',  labelKey: 'filters.finding' },
  { id: 'scan',     labelKey: 'filters.scan' },
  { id: 'agent',    labelKey: 'filters.agent' },
  { id: 'error',    labelKey: 'filters.error' },
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
  const { t } = useTranslation()
  const { activity, connected, clearActivity } = useTelemetry()
  const [filter, setFilter] = useState('all')
  const [paused, setPaused] = useState(false)
  const [now, setNow] = useState(Date.now())
  const pausedSnapshot = React.useRef([])

  React.useEffect(() => {
    const timer = setInterval(() => setNow(Date.now()), 1000)
    return () => clearInterval(timer)
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
      aria-label={t(`${NS}.ariaLabel`)}
    >
      <header className="flex items-center justify-between gap-2 px-3 py-2 border-b border-white/[0.06]">
        <div className="flex items-center gap-2 min-w-0">
          <span
            className={`inline-block w-1.5 h-1.5 rounded-full ${
              connected ? 'bg-emerald-400 animate-pulse' : 'bg-rose-500'
            }`}
            aria-hidden="true"
            title={connected ? t(`${NS}.connected`) : t(`${NS}.reconnecting`)}
          />
          <h3 className="text-[11px] font-mono uppercase tracking-[0.18em] text-white/75 truncate">
            {t(`${NS}.title`)}
          </h3>
          <span className="text-[10px] font-mono text-white/35 ml-1">
            {activity.length}
          </span>
        </div>
        <div className="flex items-center gap-1 shrink-0">
          <Button variant="unstyled"
            type="button"
            onClick={() => setPaused((p) => !p)}
            className={`text-[10px] font-mono px-2 py-0.5 rounded border ${
              paused
                ? 'border-amber-500/40 text-amber-200 bg-amber-500/10'
                : 'border-white/10 text-white/55 hover:text-white/85'
            }`}
            title={paused ? t(`${NS}.resumeTitle`) : t(`${NS}.pauseTitle`)}
            aria-pressed={paused}
          >
            {paused ? t(`${NS}.resume`) : t(`${NS}.pause`)}
          </Button>
          <Button variant="unstyled"
            type="button"
            onClick={clearActivity}
            className="text-[10px] font-mono px-2 py-0.5 rounded border border-white/10 text-white/45 hover:text-white/80"
            title={t(`${NS}.clearTitle`)}
          >
            {t(`${NS}.clear`)}
          </Button>
        </div>
      </header>

      <div className="flex items-center gap-1 px-3 py-1.5 border-b border-white/[0.04] overflow-x-auto">
        {FILTERS.map((f) => {
          const active = filter === f.id
          return (
            <Button variant="unstyled"
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
              {t(`${NS}.${f.labelKey}`)}
            </Button>
          )
        })}
      </div>

      <div
        className="overflow-y-auto divide-y divide-white/[0.04] custom-scroll"
        style={{ maxHeight }}
        aria-live="polite"
      >
        {visible.length === 0 ? (
          <div className="px-3 py-12 text-center text-[11px] font-mono text-white/35">
            {activity.length === 0
              ? t(`${NS}.waiting`)
              : t(`${NS}.noMatch`)}
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
                    <span style={{ color: meta.color }}>{t(`${NS}.${meta.labelKey}`)}</span>
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
                      {fmtAgo(e.t, now)} {t(`${NS}.ago`)}
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
