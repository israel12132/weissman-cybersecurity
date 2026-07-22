import { forwardRef } from 'react'
import { cn } from '../../lib/cn'

const SIZES = {
  sm: 'h-1.5',
  md: 'h-2.5',
  lg: 'h-3.5',
}

const VARIANTS = {
  accent: 'bg-accent-cyan',
  success: 'bg-status-active',
  warning: 'bg-severity-medium',
  danger: 'bg-severity-critical',
}

/**
 * Progress bar primitive — determinate fill or indeterminate sweep.
 *
 * @param {number} value — current progress (clamped to 0…max)
 * @param {number} max — upper bound of the scale
 * @param {'sm'|'md'|'lg'} size — track height
 * @param {'accent'|'success'|'warning'|'danger'} variant — fill color
 * @param {boolean} indeterminate — animate an unbounded sweep (omits aria-valuenow)
 * @param {boolean} showLabel — render a text row above the track
 * @param {string} label — accessible name + label-row text (defaults to the percentage)
 */
const Progress = forwardRef(function Progress(
  {
    value = 0,
    max = 100,
    size = 'md',
    variant = 'accent',
    indeterminate = false,
    showLabel = false,
    label,
    className,
    ...props
  },
  ref,
) {
  const clamped = Math.min(Math.max(Number(value) || 0, 0), max)
  const pct = max > 0 ? Math.round((clamped / max) * 100) : 0
  const fillColor = VARIANTS[variant] ?? VARIANTS.accent

  return (
    <div ref={ref} className={cn('flex flex-col gap-1.5', className)} {...props}>
      {showLabel && (
        <div className="text-xs text-text-muted">{label || `${pct}%`}</div>
      )}
      <div
        role="progressbar"
        aria-valuemin={0}
        aria-valuemax={max}
        aria-valuenow={indeterminate ? undefined : clamped}
        aria-label={label || 'Progress'}
        className={cn(
          'w-full overflow-hidden rounded-full bg-bg-3',
          SIZES[size] ?? SIZES.md,
        )}
      >
        <div
          className={cn(
            'h-full rounded-full',
            fillColor,
            indeterminate
              ? 'animate-progress-indeterminate'
              : 'transition-all duration-normal ease-out-expo',
          )}
          style={indeterminate ? undefined : { width: `${pct}%` }}
        />
      </div>
    </div>
  )
})

Progress.displayName = 'Progress'

export default Progress
export { Progress }
