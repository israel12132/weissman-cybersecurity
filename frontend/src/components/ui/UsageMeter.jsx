import { forwardRef } from 'react'
import { cn } from '../../lib/cn'

/**
 * UsageMeter — a metered usage bar for billing / quota surfaces. Shows used vs
 * limit with a fill that shifts to warning near the cap and to danger on
 * overage. Reports progress via ARIA.
 *
 * @param {React.ReactNode} [label] @param {number} used @param {number} limit
 * @param {string} [unit] — appended to the used/limit readout (e.g. "scans")
 * @param {number} [warnAt=0.8] — fraction of the limit that turns the bar amber
 * @param {Array<{at:number,label?:string}>} [tiers] — marker ticks along the track
 */
const UsageMeter = forwardRef(function UsageMeter(
  { label, used = 0, limit = 100, unit, warnAt = 0.8, tiers = [], className, ...props },
  ref,
) {
  const safeLimit = limit > 0 ? limit : 1
  const ratio = used / safeLimit
  const pct = Math.min(100, Math.max(0, ratio * 100))
  const over = used > safeLimit
  const nearing = !over && ratio >= warnAt

  const fill = over
    ? 'bg-severity-critical'
    : nearing
      ? 'bg-severity-medium'
      : 'bg-accent-cyan'

  const fmt = (n) => new Intl.NumberFormat().format(n)

  return (
    <div ref={ref} className={cn('flex flex-col gap-1.5', className)} {...props}>
      {(label != null || unit != null) && (
        <div className="flex items-baseline justify-between gap-2">
          {label != null && <span className="text-sm font-medium text-text-secondary">{label}</span>}
          <span className={cn('text-xs tabular-nums', over ? 'text-severity-critical' : 'text-text-muted')}>
            {fmt(used)} / {fmt(limit)}
            {unit ? ` ${unit}` : ''}
            {over && ' · over limit'}
          </span>
        </div>
      )}
      <div
        role="progressbar"
        aria-valuenow={Math.round(pct)}
        aria-valuemin={0}
        aria-valuemax={100}
        aria-label={typeof label === 'string' ? label : 'Usage'}
        className="relative h-2.5 w-full overflow-hidden rounded-full bg-bg-3"
      >
        <div
          className={cn('h-full rounded-full transition-all duration-normal ease-out-expo', fill)}
          style={{ width: `${pct}%` }}
        />
        {tiers.map((tier, i) => {
          const left = Math.min(100, Math.max(0, (tier.at / safeLimit) * 100))
          return (
            <span
              key={i}
              className="absolute top-0 h-full w-px bg-border-strong"
              style={{ insetInlineStart: `${left}%` }}
              aria-hidden="true"
              title={tier.label}
            />
          )
        })}
      </div>
    </div>
  )
})

UsageMeter.displayName = 'UsageMeter'

export default UsageMeter
export { UsageMeter }
