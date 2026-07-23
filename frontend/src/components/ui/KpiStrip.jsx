import { forwardRef } from 'react'
import { ArrowDownRight, ArrowUpRight, Minus } from 'lucide-react'
import { cn } from '../../lib/cn'
import Sparkline from './Sparkline.jsx'
import Skeleton from './Skeleton.jsx'

/**
 * Resolve the delta chip's semantic tone. By default a rising value is "good"
 * (success/green) and a falling value is "bad" (danger/red). For metrics where
 * up is bad (open findings, risk, MTTR), pass `invertDelta` to flip it.
 */
function deltaTone(delta, invert) {
  if (!delta) return 'flat'
  const rising = delta > 0
  const good = invert ? !rising : rising
  return good ? 'good' : 'bad'
}

const TONE_CLASSES = {
  good: 'text-status-active bg-status-active-bg',
  bad: 'text-severity-critical bg-severity-critical-bg',
  flat: 'text-text-muted bg-bg-3',
}

const SPARK_VARIANT = { good: 'success', bad: 'danger', flat: 'muted' }

/**
 * A single KPI tile: label, headline value (+ unit), a delta chip, and an
 * optional trend sparkline. Becomes a keyboard-operable drill-down when
 * `onClick` is provided.
 *
 * @param {string} label @param {string|number} value @param {string} [unit]
 * @param {number} [delta] — signed change; rendered as a tone-coloured chip
 * @param {string} [deltaLabel] — text beside the delta (e.g. "vs 24h")
 * @param {boolean} [invertDelta=false] — treat a rising value as "bad"
 * @param {Array<number>} [trend] — sparkline series
 * @param {React.ReactNode} [icon] @param {Function} [onClick] @param {boolean} [loading]
 */
const KpiTile = forwardRef(function KpiTile(
  {
    label,
    value,
    unit,
    delta,
    deltaLabel,
    invertDelta = false,
    trend,
    icon,
    onClick,
    loading = false,
    className,
    ...props
  },
  ref,
) {
  const interactive = typeof onClick === 'function'
  const Comp = interactive ? 'button' : 'div'
  const tone = deltaTone(delta, invertDelta)
  const DeltaIcon = !delta ? Minus : delta > 0 ? ArrowUpRight : ArrowDownRight

  const interactiveProps = interactive
    ? {
        type: 'button',
        onClick,
        'aria-label': `${label}: ${value}${unit ? ` ${unit}` : ''}`,
      }
    : {}

  if (loading) {
    return (
      <div
        className={cn(
          'flex flex-col gap-2 rounded-xl border border-border-default bg-bg-2 p-4',
          className,
        )}
      >
        <Skeleton className="h-3 w-20" />
        <Skeleton className="h-7 w-24" />
        <Skeleton className="h-6 w-full" />
      </div>
    )
  }

  return (
    <Comp
      ref={ref}
      className={cn(
        'group relative flex flex-col gap-2 rounded-xl border border-border-default bg-bg-2 p-4 text-start',
        'transition-all duration-normal ease-out-expo',
        interactive && [
          'cursor-pointer hover:-translate-y-px hover:border-border-strong hover:bg-bg-3',
          'focus-visible:outline-none focus-visible:shadow-[var(--focus-ring)]',
        ],
        className,
      )}
      {...interactiveProps}
      {...props}
    >
      <div className="flex items-center justify-between gap-2">
        <span className="text-[10px] font-medium uppercase tracking-widest text-text-muted">
          {label}
        </span>
        {icon && (
          <span className="text-text-tertiary [&>svg]:size-4" aria-hidden="true">
            {icon}
          </span>
        )}
      </div>

      <div className="flex items-end gap-1.5">
        <span className="font-display text-2xl font-semibold leading-none text-text-primary tabular-nums">
          {value}
        </span>
        {unit && <span className="pb-0.5 text-xs text-text-tertiary">{unit}</span>}
      </div>

      <div className="flex items-center justify-between gap-2">
        {delta != null ? (
          <span
            className={cn(
              'inline-flex items-center gap-0.5 rounded-md px-1.5 py-0.5 text-[11px] font-medium tabular-nums',
              TONE_CLASSES[tone],
            )}
          >
            <DeltaIcon className="size-3" aria-hidden="true" />
            {delta > 0 ? '+' : ''}
            {delta}
            {deltaLabel && <span className="ms-1 font-normal opacity-70">{deltaLabel}</span>}
          </span>
        ) : (
          <span />
        )}
        {Array.isArray(trend) && trend.length > 0 && (
          <Sparkline data={trend} variant={SPARK_VARIANT[tone]} width={72} height={22} />
        )}
      </div>
    </Comp>
  )
})

KpiTile.displayName = 'KpiTile'

/**
 * A responsive row of KPI tiles. Pass `items` (array of KpiTile props) or
 * compose <KpiTile> children directly.
 *
 * @param {Array<object>} [items] @param {number} [columns] — fixed column count
 * @param {boolean} [loading] — render skeleton tiles
 */
function KpiStrip({ items, columns, loading = false, className, children, ...props }) {
  const gridStyle = columns
    ? { gridTemplateColumns: `repeat(${columns}, minmax(0, 1fr))` }
    : undefined
  return (
    <div
      className={cn(
        'grid gap-3',
        !columns && 'grid-cols-[repeat(auto-fit,minmax(11rem,1fr))]',
        className,
      )}
      style={gridStyle}
      {...props}
    >
      {children ??
        (items || []).map((item, i) => (
          <KpiTile key={item.id ?? item.label ?? i} loading={loading} {...item} />
        ))}
    </div>
  )
}

export default KpiStrip
export { KpiStrip, KpiTile }
