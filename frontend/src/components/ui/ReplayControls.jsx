import { useId } from 'react'
import { Pause, Play, SkipBack, SkipForward } from 'lucide-react'
import { cn } from '../../lib/cn'

const SPEEDS = [0.5, 1, 2, 4]

function defaultFormat(seconds) {
  const s = Math.max(0, Math.floor(seconds))
  const m = Math.floor(s / 60)
  const r = s % 60
  return `${m}:${String(r).padStart(2, '0')}`
}

/**
 * ReplayControls — a timeline scrubber for WarRoom / incident replay. Controlled:
 * the parent owns the tick loop and playback state; this renders the transport
 * (play/pause, skip, speed) and a seekable progress slider.
 *
 * @param {number} value — current position @param {number} [min=0] @param {number} max
 * @param {boolean} [playing=false] @param {number} [speed=1]
 * @param {(v:number)=>void} onSeek @param {()=>void} onTogglePlay @param {(s:number)=>void} [onSpeedChange]
 * @param {(seconds:number)=>string} [formatTime]
 */
export default function ReplayControls({
  value = 0,
  min = 0,
  max = 100,
  playing = false,
  speed = 1,
  onSeek,
  onTogglePlay,
  onSpeedChange,
  formatTime = defaultFormat,
  className,
  ...props
}) {
  const uid = useId()
  const clamped = Math.min(max, Math.max(min, value))

  return (
    <div
      className={cn('flex flex-col gap-2 rounded-xl border border-border-default bg-bg-2 p-3', className)}
      {...props}
    >
      <div className="flex items-center gap-2">
        <button
          type="button"
          onClick={() => onSeek?.(min)}
          aria-label="Skip to start"
          className="rounded-lg p-1.5 text-text-muted hover:text-text-secondary focus-visible:outline-none focus-visible:shadow-[var(--focus-ring)]"
        >
          <SkipBack className="size-4" aria-hidden="true" />
        </button>
        <button
          type="button"
          onClick={onTogglePlay}
          aria-label={playing ? 'Pause replay' : 'Play replay'}
          aria-pressed={playing}
          className="inline-flex size-9 items-center justify-center rounded-lg bg-accent-gradient text-text-inverse focus-visible:outline-none focus-visible:shadow-[var(--focus-ring)]"
        >
          {playing ? <Pause className="size-4" aria-hidden="true" /> : <Play className="size-4" aria-hidden="true" />}
        </button>
        <button
          type="button"
          onClick={() => onSeek?.(max)}
          aria-label="Skip to end"
          className="rounded-lg p-1.5 text-text-muted hover:text-text-secondary focus-visible:outline-none focus-visible:shadow-[var(--focus-ring)]"
        >
          <SkipForward className="size-4" aria-hidden="true" />
        </button>

        <span className="ms-1 text-xs tabular-nums text-text-secondary">
          {formatTime(clamped)} <span className="text-text-muted">/ {formatTime(max)}</span>
        </span>

        <label htmlFor={`${uid}-speed`} className="ms-auto flex items-center gap-1.5 text-[11px] text-text-muted">
          Speed
          <select
            id={`${uid}-speed`}
            value={String(speed)}
            onChange={(e) => onSpeedChange?.(Number(e.target.value))}
            className="rounded-md border border-border-default bg-bg-1 px-1.5 py-1 text-xs text-text-primary outline-none focus-visible:shadow-[var(--focus-ring)]"
          >
            {SPEEDS.map((s) => (
              <option key={s} value={s}>
                {s}×
              </option>
            ))}
          </select>
        </label>
      </div>

      <input
        type="range"
        min={min}
        max={max}
        value={clamped}
        onChange={(e) => onSeek?.(Number(e.target.value))}
        aria-label="Replay position"
        aria-valuetext={formatTime(clamped)}
        className="w-full accent-[color:var(--accent-cyan)]"
      />
    </div>
  )
}

export { ReplayControls }
